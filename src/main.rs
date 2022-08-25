use std::{
    fmt::Write,
    fs::File,
    io::Write as IoWrite,
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    process::exit,
    str::FromStr,
};

use colorful::Colorful;
use futures_util::StreamExt;
use indicatif::{ProgressBar, ProgressState, ProgressStyle};
use maxminddb::geoip2;
use trust_dns_resolver::{
    config::{NameServerConfig, ResolverConfig, ResolverOpts},
    Resolver,
};

macro_rules! info {
    ($($arg:tt)*) => {
        print!("{}", colorful::Colorful::green("INFO:  "));
        println!($($arg)*)
    }
}

macro_rules! error {
    ($($arg:tt)*) => {
        print!("{}", colorful::Colorful::red("ERROR: "));
        println!($($arg)*)
    }
}

// macro_rules! warn {
//     ($($arg:tt)*) => {
//         print!("{}", colorful::Colorful::yellow("WARN:  "));
//         println!($($arg)*)
//     }
// }

enum Protocol {
    Normal,
    OverTls,
    OverHttps,
}

fn parse_addr<S: AsRef<str>>(addr: S, default_port: u16) -> anyhow::Result<SocketAddr> {
    let addr = addr.as_ref();
    let mut parts = addr.split(':');
    let host = parts.next().ok_or(anyhow::anyhow!("missing host"))?;
    let port = parts
        .next()
        .map(|p| u16::from_str(p).unwrap_or(default_port));
    Ok(SocketAddr::new(
        host.parse().or(Err(anyhow::anyhow!("invalid host")))?,
        port.unwrap_or(default_port),
    ))
}

fn get_resolver_config<S: AsRef<str>>(
    nameservers: Vec<S>,
    protocol: Protocol,
) -> anyhow::Result<ResolverConfig> {
    Ok(if nameservers.is_empty() {
        match protocol {
            Protocol::Normal => ResolverConfig::default(), // Google Public DNS
            Protocol::OverTls => ResolverConfig::cloudflare_tls(), // Cloudflare over TLS
            Protocol::OverHttps => ResolverConfig::cloudflare_https(), // Cloudflare over HTTPS
        }
    } else {
        let mut config = ResolverConfig::new();
        for nameserver in nameservers {
            match protocol {
                Protocol::Normal => {
                    config.add_name_server(NameServerConfig {
                        socket_addr: parse_addr(&nameserver, 53)?,
                        protocol: trust_dns_resolver::config::Protocol::Udp,
                        tls_dns_name: None,
                        trust_nx_responses: false,
                        tls_config: None,
                        bind_addr: None,
                    });
                    // TCP
                    config.add_name_server(NameServerConfig {
                        socket_addr: parse_addr(nameserver, 53)?,
                        protocol: trust_dns_resolver::config::Protocol::Tcp,
                        tls_dns_name: None,
                        trust_nx_responses: false,
                        tls_config: None,
                        bind_addr: None,
                    });
                }
                Protocol::OverTls => {
                    // 1.1.1.1:853|cloudflare-dns.com
                    // 1.1.1.1:853
                    // Split on |
                    let mut parts = nameserver.as_ref().split('|');
                    config.add_name_server(NameServerConfig {
                        socket_addr: parse_addr(
                            parts
                                .next()
                                .ok_or(anyhow::anyhow!("please provide a valid ip address"))?,
                            853,
                        )?,
                        protocol: trust_dns_resolver::config::Protocol::Tls,
                        tls_dns_name: parts.next().map(|s| s.to_string()),
                        trust_nx_responses: false,
                        tls_config: None,
                        bind_addr: None,
                    })
                }
                Protocol::OverHttps => {
                    // Similarly to OverTls, but with HTTPS
                    let mut parts = nameserver.as_ref().split('|');
                    config.add_name_server(NameServerConfig {
                        socket_addr: parse_addr(
                            parts
                                .next()
                                .ok_or(anyhow::anyhow!("please provide a valid ip address"))?,
                            443,
                        )?,
                        protocol: trust_dns_resolver::config::Protocol::Https,
                        tls_dns_name: parts.next().map(|s| s.to_string()),
                        trust_nx_responses: false,
                        tls_config: None,
                        bind_addr: None,
                    })
                }
            }
        }
        config
    })
}

fn resolve<S: AsRef<str>>(
    name: S,
    nameservers: Vec<S>,
    protocol: Protocol,
) -> anyhow::Result<Vec<String>> {
    let config = get_resolver_config(nameservers, protocol)?;
    info!(
        "Resolving \'{}\' through these nameservers:",
        name.as_ref().light_cyan()
    );
    for nameserver in config.name_servers() {
        println!(" - {}", nameserver.to_string().blue());
    }
    let opts = ResolverOpts::default();
    let resolver = Resolver::new(config, opts)?;
    let response = resolver.lookup_ip(format!("{}", name.as_ref()))?;
    let addresses = response.iter().map(|r| r.to_string()).collect();
    Ok(addresses)
}

#[derive(Debug, Default)]
struct GeoData {
    city: Option<String>,
    country: Option<String>,
    asn: Option<String>,
    isp: Option<String>,
    anonymous: Option<String>,
}

async fn download_db<'a, S: AsRef<str>>(url: S, save: &PathBuf) -> anyhow::Result<()> {
    info!(
        "Downloading GeoIP db from\n\"{}\" to\n\"{}\"",
        url.as_ref().light_cyan(),
        save.display().to_string().light_cyan()
    );
    let resp = reqwest::get(url.as_ref()).await?;
    if !resp.status().is_success() {
        return Err(anyhow::anyhow!("failed to download {}", url.as_ref()));
    }
    let pb = ProgressBar::new(resp.content_length().unwrap_or(0) as u64);

    let mut resp = resp.bytes_stream();

    pb.set_style(
        ProgressStyle::with_template(
            "[{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({eta})",
        )
        .unwrap()
        .with_key("eta", |state: &ProgressState, w: &mut dyn Write| {
            write!(w, "{:.1}s", state.eta().as_secs_f64()).unwrap()
        })
        .progress_chars("#>-"),
    );

    let mut file = File::create(save)?;

    while let Some(chunk) = resp.next().await {
        let chunk = chunk?;
        file.write_all(&chunk)?;
        pb.inc(chunk.len() as u64);
    }

    pb.finish_with_message("Done");

    Ok(())
}

fn get_geo_data<'a, S: AsRef<str>>(ip: S, db: &PathBuf) -> anyhow::Result<GeoData> {
    let reader = maxminddb::Reader::open_readfile(db)?;
    let ip = ip.as_ref().parse::<IpAddr>()?;
    let mut data = GeoData::default();
    if let Ok(city) = reader.lookup::<geoip2::City>(ip) {
        if let Some(city) = city.city {
            if let Some(names) = city.names {
                data.city = names.get("en").map(|s| s.to_string());
            }
        }
        if let Some(country) = city.country {
            if let Some(names) = country.names {
                data.country = names.get("en").map(|s| s.to_string());
            }
            if let Some(iso_code) = country.iso_code {
                if let Some(country) = data.country {
                    data.country = Some(format!("{} ({})", country, iso_code));
                } else {
                    data.country = Some(iso_code.to_string());
                }
            }
        }
    }

    if let Ok(isp) = reader.lookup::<geoip2::Isp>(ip) {
        if let Some(number) = isp.autonomous_system_number {
            data.asn = Some(number.to_string());
        }
        if let Some(org) = isp.autonomous_system_organization {
            if let Some(asn) = data.asn {
                data.asn = Some(format!("{} ({})", org, asn));
            } else {
                data.asn = Some(org.to_string());
            }
        }
        if let Some(isp) = isp.isp {
            data.isp = Some(isp.to_string());
        }
    }
    if let Ok(anonymous) = reader.lookup::<geoip2::AnonymousIp>(ip) {
        dbg!(anonymous);
    }
    Ok(data)
}

fn main() {
    let default_save_path = directories::ProjectDirs::from("", "", "geoip")
        .unwrap_or(directories::ProjectDirs::from_path(".".parse().unwrap()).unwrap());

    // If is not directory, create it
    if !default_save_path.cache_dir().is_dir() {
        std::fs::create_dir_all(&default_save_path.cache_dir()).unwrap();
    }

    let default_save_path = default_save_path.cache_dir().join("GeoData.mmdb");

    let cmd = clap::Command::new("geoip")
        .bin_name("geoip")
        .version(clap::crate_version!())
        .author(clap::crate_authors!())
        .subcommand_required(false)
        .arg(
            clap::Arg::new("name")
                .help("The name(or IP address) to locate")
                .required(true),
        )
        .arg(
            clap::Arg::new("nameservers")
                .long("ns")
                .help("The nameservers to use")
                .required(false)
                .value_delimiter(',')
        )
        .arg(
            clap::Arg::new("protocol")
                .long("protocol")
                .short('p')
                .help("The protocol to use")
                .required(false)
                .possible_values(&["normal", "tls", "https"])
                .default_value("normal"),
        )
        .arg(
            clap::Arg::new("database")
                .long("database")
                .short('d')
                .help("The database to use, path or url")
                .required(false)
                .default_value("https://ghproxy.com/https://raw.githubusercontent.com/P3TERX/GeoLite.mmdb/download/GeoLite2-City.mmdb"),
        )
        .arg(
            clap::Arg::new("save")
                .long("save")
                .short('s')
                .help("Save the database to the given path")
                .required(false)
                .default_value(default_save_path.to_str().unwrap())
        )
        .arg(
            clap::Arg::new("force")
                .short('f')
                .help("Force to download the database")
                .action(clap::ArgAction::SetTrue)
                .required(false)
                
        );
    let matches = cmd.get_matches();
    let name = matches.value_of("name").unwrap();
    let nameservers = matches
        .values_of("nameservers")
        .unwrap_or(clap::Values::default())
        .collect::<Vec<_>>();
    let protocol = match matches.value_of("protocol").unwrap_or("normal") {
        "normal" => Protocol::Normal,
        "tls" => Protocol::OverTls,
        "https" => Protocol::OverHttps,
        _ => unreachable!(),
    };
    let database = matches.value_of("database").unwrap();
    let save = matches
        .value_of("save")
        .unwrap()
        .parse::<PathBuf>()
        .unwrap();

    let database = if database.starts_with("https://") || database.starts_with("http://") {
        if save.is_file() && !matches.get_one::<bool>("force").unwrap() {
            info!("Database already exists, skipping download");
            save
        } else {
            // block on download_db(database, &save)
            let rt = tokio::runtime::Runtime::new().unwrap();

            if let Err(e) = rt.block_on(download_db(database, &save)) {
                error!("Unable to download database: {}", e);
                exit(1);
            }

            save
        }
    } else {
        let path = database.parse::<PathBuf>().unwrap();
        if !path.is_file() {
            error!("Database file not found");
            exit(1);
        }
        path
    };

    if !database.is_file() {
        error!("The database is not a file");
        exit(1);
    }

    let ips = if let Ok(_) = name.parse::<std::net::Ipv4Addr>() {
        Ok(vec![name.to_string()])
    } else {
        resolve(name, nameservers, protocol)
    };
    
    if let Err(e) = ips {
        error!("Failed to resolve {}: {}", name.light_cyan(), e);
        exit(1);
    }
    let ips = ips.unwrap();
    info!(
        "Querying GeoIP data for {} ips...",
        ips.len().to_string().light_cyan()
    );
    for ip in ips {
        match get_geo_data(&ip, &database) {
            Ok(geo_data) => {
                println!(" - {} {{", ip.as_str().light_cyan());
                if let Some(country) = geo_data.country {
                    println!("   {}: {}", "Country", country.blue());
                }
                if let Some(city) = geo_data.city {
                    println!("   {}: {}", "City", city.blue());
                }
                if let Some(asn) = geo_data.asn {
                    println!("   {}: {}", "ASN", asn.blue());
                }
                if let Some(isp) = geo_data.isp {
                    println!("   {}: {}", "ISP", isp.blue());
                }
                if let Some(anonymous) = geo_data.anonymous {
                    println!("   {}: {}", "Anonymous", anonymous.blue());
                }
                println!(" }}");
            }
            Err(e) => {
                error!("Failed to get geo data for {}: {}", ip, e);
            }
        }
    }
}

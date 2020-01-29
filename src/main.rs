use std::io;
use std::io::BufReader;
use std::net::ToSocketAddrs;
use std::path::PathBuf;
use std::sync::Arc;
use structopt::StructOpt;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::prelude::*;
use tokio_rustls::{rustls::ClientConfig, webpki::DNSNameRef, TlsConnector};

use serde::Deserialize;

use slog::{debug, error, info, o, Logger};

use failure::{format_err, Error};

enum State<'a, 'b> {
    Login(&'a String, &'b String),
    WaitAuthenticated,
    WaitSelected,
    WaitIdle,
    Idle,
}

#[derive(Deserialize, Debug)]
struct Config {
    accounts: Vec<Account>,
}

#[derive(Deserialize, Debug, Clone)]
struct Account {
    /// Host of IMAP server.
    host: String,

    /// Port for IMAP server.
    port: Option<i16>,

    /// Username to use for authentication.
    user: String,

    /// Password to use for authentication.
    pass: String,

    /// IMAP folders to watch for updates.
    folders: Vec<Folder>,
}

#[derive(Deserialize, Debug, Clone)]
struct Folder {
    name: String,
}

#[derive(Debug, StructOpt)]
#[structopt(
    name = "imap-notifier",
    about = "Runs a script when an email arrives to the folder or the folder's emails change."
)]
struct Options {
    #[structopt(short = "c", long = "config", default_value = "config.json")]
    config: std::path::PathBuf,

    /// Script to be ran on notify. EXISTS is passed on new email, FLAGS with the flags are passed on read/update/delete.
    #[structopt(parse(from_os_str))]
    script: PathBuf,

    /// Path to CA certificates. Defaults to system store.
    #[structopt(long = "cafile")]
    cafile: Option<std::path::PathBuf>,
}

fn main() -> Result<(), Error> {
    let root = get_root_logger();

    debug!(root, "imap notifier start");
    let opt = Options::from_args();
    let cfg: Config = serde_json::from_str(
        &std::fs::read_to_string(opt.config)
            .map_err(|e| format_err!("error reading config: {}", e))?,
    )?;

    let mut config = ClientConfig::new();
    if let Some(cafile) = &opt.cafile {
        let mut pem = BufReader::new(std::fs::File::open(cafile)?);
        config
            .root_store
            .add_pem_file(&mut pem)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid cert"))?;
    } else {
        config
            .root_store
            .add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);
    }
    let config = Arc::new(config);

    // Create the runtime
    let mut rt = tokio::runtime::Builder::new()
        .threaded_scheduler()
        .enable_all()
        .build()?;

    // let mut tasks: Vec<_> = vec![];
    let script = opt.script.clone();
    let tasks = cfg
        .accounts
        .iter()
        .map(|account| {
            let mut accounts = Vec::with_capacity(account.folders.len());
            accounts.resize(account.folders.len(), account.clone());

            account.folders.iter().zip(accounts).map(|(folder, acct)| {
                rt.spawn(watch(
                    // root.new(o!("name" => format!("{} on {}", folder.name, &folder_acct.host))),
                    root.new(o!("folder" => folder.clone().name, "host" => acct.clone().host)),
                    acct.clone(),
                    folder.name.clone(),
                    script.clone(),
                    config.clone(),
                ))
            })
        })
        .flatten()
        .collect::<Vec<_>>(); // drain to evaluate lazy iter

    let mut size = tasks.len();

    let mut handle = futures::future::select_all(tasks);
    // https://docs.rs/futures-preview/0.3.0-alpha.18/futures/future/fn.select_all.html
    // 0 is the future that finished, futs is the reaiming ones.
    while size > 0 {
        debug!(root, "{} tasks remaining", size);
        let (fut, new_size, futs) = rt.block_on(handle);
        size = new_size;
        fut?.unwrap();

        handle = futures::future::select_all(futs);
    }

    // Wait until the runtime becomes idle and shut it down.
    Ok(())
}

// todo: poll @ 29 minute intervals https://tools.ietf.org/html/rfc2177 pg 1 last para
async fn watch<'a>(
    logger: Logger,
    account: Account,
    folder: String,
    script: PathBuf,
    config: Arc<ClientConfig>,
) -> Result<(), Error> {
    info!(logger, "starting watcher: {} on {}", folder, account.host);

    let (host, _port, fullhost): (&str, &str, &str) = if !account.host.contains(":") {
        (account.host.as_str(), "993", &account.host)
    } else {
        let parts = account.host.split(':').collect::<Vec<_>>();
        if parts.len() != 2 {
            info!(logger, "expected exactly two host parts: {:?}", parts);
            return Err(format_err!(
                "expected exactly two host parts, got {} in '{}'",
                parts.len(),
                account.host
            ));
        }

        let (host, port) = (parts[0], parts[1]);

        (host, port, account.host.as_str())
    };

    let domain = DNSNameRef::try_from_ascii_str(host)
        .map_err(|e| format_err!("error when parsing dns name '{}': {}", fullhost, e))?;
    let host = fullhost
        .to_socket_addrs()?
        .next()
        .ok_or(format_err!("Unable to parse host"))?;

    debug!(logger, "starting stream");
    let stream = TlsConnector::from(config)
        .connect(domain, TcpStream::connect(host).await?)
        .await?;
    let (read, mut write) = tokio::io::split(stream);
    debug!(logger, "connected!");

    use tokio::stream::StreamExt;

    let mut state = State::Login(&account.user, &account.pass);

    let mut stream = tokio::io::BufReader::new(read).lines().map(|line| {
        if line.is_err() {
            error!(logger, "-> ERR: {:?}", line.err());
            return None;
        }
        let line = line.unwrap();

        info!(logger, "-> {}", line);

        if line.starts_with(". NO [AUTHENTICATIONFAILED]") {
            error!(logger, "Authentication failed, quitting.");
            return Some(". CLOSE".to_owned());
        }

        if line.starts_with(". BAD") {
            error!(logger, "Sent an invalid command.");
            return Some(". CLOSE".to_owned());
        }

        if line.starts_with("* BYE") {
            info!(logger, "Remote said goodbye.");
            panic!("byte");
        }

        use State::*;
        match state {
            Login(user, pass) => {
                state = WaitAuthenticated;
                return Some(format!(". LOGIN \"{}\" \"{}\"", user, pass));
            }
            WaitAuthenticated => {
                if line.contains("Logged in") {
                    state = WaitSelected;
                    return Some(". select ".to_owned() + &folder);
                }

                return None;
            }
            WaitSelected => {
                if line.contains("Select completed") {
                    debug!(logger, "waiting for idling confirmation");
                    state = WaitIdle;
                    return Some(". idle".to_owned());
                }

                return None;
            }
            WaitIdle => {
                if line.contains("+ idling") {
                    debug!(logger, "idle confirmed");
                    state = Idle;
                }

                return None;
            }
            Idle => {
                if line.contains("FETCH (FLAGS") {
                    debug!(logger, "Calling script");
                    let output = call_command(
                        &script,
                        vec![
                            "FLAGS",
                            &account.user,
                            &folder,
                            &get_flags(&line).unwrap().unwrap(),
                        ],
                    )
                    .unwrap();

                    debug!(logger, "STDOUT: {}", output.0);
                    debug!(logger, "STDERR: {}", output.1);
                }

                if line.contains(" EXISTS") {
                    debug!(logger, "Calling script");
                    let output =
                        call_command(&script, vec!["EXISTS", &account.user, &folder]).unwrap();

                    debug!(logger, "STDOUT: {}", output.0);
                    debug!(logger, "STDERR: {}", output.1);
                }

                return None;
            }
        }
    });

    while let Some(res) = stream.next().await {
        match res {
            Some(out) => {
                let len = out.len();
                info!(logger, "<- {}", out.clone());
                let size = write.write((out + "\r\n").as_bytes()).await? - 2;
                if len != size {
                    return Err(format_err!(
                        "written size differs from actual: {} != {}",
                        size,
                        len
                    ));
                }
            }
            None => (),
            /*
            Err(e) => {
                return Err(format_err!("err: {}", e));
            }*/
        }
    }

    Ok(())
}

fn call_command<T, S, R>(command: &R, args: T) -> Result<(String, String), Error>
where
    T: IntoIterator<Item = S>,
    S: AsRef<std::ffi::OsStr>,
    R: AsRef<std::ffi::OsStr>,
{
    use std::process::Command;
    let output = Command::new(command)
        .args(args)
        .spawn()?
        .wait_with_output()?;

    Ok((
        String::from_utf8(output.stdout)?,
        String::from_utf8(output.stderr)?,
    ))
}

fn get_flags(line: &str) -> Result<Option<String>, Error> {
    use regex::Regex;

    let re = Regex::new(r#"FETCH ?\(FLAGS ?\(([\\ A-Za-z0-9]+?)\)\)"#)?;
    match re.captures(line) {
        Some(captures) => Ok(captures.get(0).map(|v| v.as_str().to_owned())),
        None => Ok(None),
    }
}

fn get_root_logger() -> Logger {
    use sloggers::terminal::{Destination, TerminalLoggerBuilder};
    use sloggers::types::Severity;
    use sloggers::Build;

    let mut builder = TerminalLoggerBuilder::new();
    builder.level(Severity::Debug);
    builder.destination(Destination::Stderr);

    let logger = builder.build().unwrap();
    logger
}

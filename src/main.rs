use futures::stream::Stream;
use std::io;
use std::io::BufReader;
use std::net::ToSocketAddrs;
use std::path::PathBuf;
use std::sync::Arc;
use std::task::Poll::{Pending, Ready};
use structopt::StructOpt;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::runtime;
use tokio_rustls::{rustls::ClientConfig, webpki::DNSNameRef, TlsConnector};

use futures::future::FutureExt;

use failure::{format_err, Error};
use log::{debug, error, info};

enum State<'a, 'b, 'c> {
    Login(&'a String, &'b String),
    WaitAuthenticated,
    SelectFolder(&'c String),
    WaitSelected,
    RequestIdle,
    WaitIdle,
    Idle,
}

#[derive(Debug, StructOpt)]
#[structopt(
    name = "imap-notifier",
    about = "Runs a script when an email arrives to the folder or the folder's emails change."
)]
struct Options {
    /// Host of IMAP server.
    host: String,

    /// Port for IMAP server.
    #[structopt(short = "p", long = "port", default_value = "993")]
    port: i16,

    /// Username to use for authentication.
    user: String,

    /// Password to use for authentication.
    pass: String,

    /// IMAP folders to watch for updates.
    folder: String,
    // folder: Vec<String>,
    /// Script to be ran on notify. EXISTS is passed on new email, FLAGS with the flags are passed on read/update/delete.
    #[structopt(parse(from_os_str))]
    script: PathBuf,

    /// Path to CA certificates. Defaults to system store.
    #[structopt(long = "cafile")]
    cafile: Option<std::path::PathBuf>,
}

fn main() -> Result<(), Error> {
    pretty_env_logger::init();

    debug!("imap notifier start");
    let opt = Options::from_args();

    let mut runtime = runtime::Builder::new()
        .basic_scheduler()
        .enable_io()
        .build()?;

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

    runtime.block_on(watch(
        opt.host, opt.folder, opt.user, opt.pass, opt.script, config,
    ))
}

// todo: poll @ 29 minute intervals https://tools.ietf.org/html/rfc2177 pg 1 last para

async fn watch<'a>(
    host: String,
    folder: String,
    user: String,
    pass: String,
    script: PathBuf,
    config: Arc<ClientConfig>,
) -> Result<(), Error> {
    let connector = TlsConnector::from(config);

    let domain = DNSNameRef::try_from_ascii_str(&host)
        .map_err(|e| format_err!("error when parsing dns name '{}': {}", host, e))?;
    let host = host
        .to_socket_addrs()?
        .next()
        .ok_or(format_err!("Unable to parse host"))?;

    let stream = TcpStream::connect(host).await?;
    let stream = connector.connect(domain, stream).await?;
    let (mut read, mut write) = tokio::io::split(stream);

    let read_stream = futures::stream::poll_fn(move |ctx| {
        use std::future::Future;

        let mut buff = vec![];

        while let Ready(Ok(c)) = Future::poll(std::pin::Pin::new(&mut read.read_u8()), ctx) {
            if c == '\r' as u8 || c == '\n' as u8 {
                break;
            }

            buff.push(c);
        }

        if buff.len() > 0 {
            Ready(String::from_utf8(buff).ok())
        } else {
            Pending
        }
    });

    use futures_util::stream::StreamExt;

    let mut state = State::Login(&user, &pass);
    let stream = read_stream
        .then(|line| {
            info!("-> {}", line);

            if line.starts_with(". NO [AUTHENTICATIONFAILED]") {
                error!("Authentication failed, quitting.");
                return futures::future::ok(Some(". CLOSE".to_owned()));
            }

            if line.starts_with(". BAD") {
                error!("Sent an invalid command.");
                return futures::future::ok(Some(". CLOSE".to_owned()));
            }

            if line.starts_with("* BYE") {
                info!("Remote said goodbye.");
                return futures::future::err(format_err!("remote hung up"));
            }

            use State::*;
            match state {
                Login(user, pass) => {
                    state = WaitAuthenticated;
                    return futures::future::ok(Some(format!(". LOGIN \"{}\" \"{}\"", user, pass)));
                }
                WaitAuthenticated => {
                    state = if line.contains("Logged in") {
                        SelectFolder(&folder)
                    } else {
                        WaitAuthenticated
                    };
                    return futures::future::ok(None);
                }
                SelectFolder(folder) => {
                    state = WaitSelected;
                    return futures::future::ok(Some(". select ".to_owned() + folder));
                }
                WaitSelected => {
                    state = if line.contains("Select completed") {
                        RequestIdle
                    } else {
                        WaitSelected
                    };
                    return futures::future::ok(None);
                }
                RequestIdle => {
                    state = WaitIdle;
                    info!("waiting for idling confirmation");

                    return futures::future::ok(Some(". idle".to_owned()));
                }
                WaitIdle => {
                    state = if line.contains("+ idling") {
                        info!("idle confirmed");
                        Idle
                    } else {
                        WaitIdle
                    };

                    return futures::future::ok(None);
                }
                Idle => {
                    if line.contains("FETCH (FLAGS") {
                        info!("Calling script");
                        let output = call_command(
                            &script,
                            vec!["FLAGS", &user, &folder, &get_flags(&line).unwrap().unwrap()],
                        )
                        .unwrap();

                        debug!("STDOUT: {}", output.0);
                        debug!("STDERR: {}", output.1);
                    }

                    if line.contains(" EXISTS") {
                        info!("Calling script");
                        let output = call_command(&script, vec!["EXISTS", &user, &folder]).unwrap();

                        debug!("STDOUT: {}", output.0);
                        debug!("STDERR: {}", output.1);
                    }

                    return futures::future::ok(None);
                }
            }
        })
        .filter(|v| futures::future::ready(!(v.is_ok() && v.as_ref().unwrap().is_none())));

    for res in futures::executor::block_on_stream(stream) {
        match res {
            Ok(Some(out)) => {
                let len = out.len();
                let size = write.write((out + "\r\n").as_bytes()).await?;
                if len != size {
                    return Err(format_err!(
                        "written size differs from actual: {} != {}",
                        size,
                        len
                    ));
                }
            }
            Ok(None) => (),
            Err(e) => {
                return Err(format_err!("err: {}", e));
            }
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

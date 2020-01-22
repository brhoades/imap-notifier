use std::io;
use std::io::BufReader;
use std::net::ToSocketAddrs;
use std::path::PathBuf;
use structopt::StructOpt;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::runtime;
use tokio_rustls::{rustls::ClientConfig, webpki::DNSNameRef, TlsConnector};

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
#[structopt(name = "imap-notifier", about = "Runs a script when an email arrives.")]
struct Options {
	// host of imap server
	host: String,

	// port
	#[structopt(short = "p", long = "port", default_value = "993")]
	port: i16,

	// username to use
	user: String,

	// password to use
	pass: String,

	// folder to watch
	folder: String,

	// Script to run
	#[structopt(parse(from_os_str))]
	script: PathBuf,

	// ca file to use for custom cert.
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
	let connector = TlsConnector::from(std::sync::Arc::new(config));
	let host = opt.host.clone();
	let domain = DNSNameRef::try_from_ascii_str(&host)
		.map_err(|e| format_err!("error when parsing dns name '{}': {}", opt.host, e))?;

	runtime.block_on(run(opt, connector, domain))
}

async fn run<'a>(
	opt: Options,
	connector: TlsConnector,
	domain: DNSNameRef<'a>,
) -> Result<(), Error> {
	let host = format!("{}:{}", opt.host, opt.port)
		.to_socket_addrs()?
		.next()
		.ok_or(format_err!("Unable to parse host"))?;

	let stream = TcpStream::connect(host).await?;
	let mut stream = connector.connect(domain, stream).await?;

	let mut state = State::Login(&opt.user, &opt.pass);

	loop {
		let mut buff = std::vec::Vec::with_capacity(1024 * 1024);
		buff.resize(128, 0);

		stream.read(&mut buff).await?;

		let lines = buff
			.split(|c| *c == '\r' as u8 || *c == '\n' as u8)
			.filter(|e| e.len() != 0)
			.map(std::str::from_utf8);

		for incoming_line in lines {
			let line = incoming_line?;

			info!("-> {}", line.replace("\r\n", ""));

			if line.starts_with(". NO [AUTHENTICATIONFAILED]") {
				error!("Authentication failed, quitting.");
				stream.write_all(". CLOSE\r\n".as_bytes()).await?;
			}

			if line.starts_with(". BAD") {
				error!("Sent an invalid command.");
				stream.write_all(". CLOSE\r\n".as_bytes()).await?;
			}

			if line.starts_with("* BYE") {
				info!("Remote said goodbye.");
				return Ok(());
			}

			use State::*;
			state = match state {
				Login(user, pass) => {
					stream
						.write_all(format!(". LOGIN \"{}\" \"{}\"\r\n", user, pass).as_bytes())
						.await?;
					WaitAuthenticated
				}
				WaitAuthenticated => {
					if line.contains("Logged in") {
						SelectFolder(&opt.folder)
					} else {
						WaitAuthenticated
					}
				}
				SelectFolder(folder) => {
					stream
						.write_all(format!(". select {}\r\n", folder).as_bytes())
						.await?;

					WaitSelected
				}
				WaitSelected => {
					if line.contains("Select completed") {
						RequestIdle
					} else {
						WaitSelected
					}
				}
				RequestIdle => {
					stream.write_all(". idle\r\n".as_bytes()).await?;

					WaitIdle
				}
				WaitIdle => {
					if line.contains("+ idling") {
						Idle
					} else {
						WaitIdle
					}
				}
				Idle => {
					if line.contains(" FETCH(FLAGS") {
						let output = call_command(
							&opt.script,
							vec!["FLAGS", &opt.user, &get_flags(&line)?.unwrap()],
						)?;

						debug!("STDOUT: {}", output.0);
						debug!("STDERR: {}", output.1);
					}

					if line.contains(" EXISTS") {
						let output = call_command(&opt.script, vec!["EXISTS", &opt.user])?;

						debug!("STDOUT: {}", output.0);
						debug!("STDERR: {}", output.1);
					}

					Idle
				}
			};
		}
	}
}

fn call_command<T, S>(command: &PathBuf, args: T) -> Result<(String, String), Error>
where
	T: IntoIterator<Item = S>,
	S: AsRef<std::ffi::OsStr>,
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

	let re = Regex::new(r#"FETCH \\(FLAGS \\(([\\ A-Za-z0-9]*?)\\)\\)"#)?;
	match re.captures(line) {
		Some(captures) => Ok(captures.get(0).map(|v| v.as_str().to_owned())),
		None => Ok(None),
	}
}

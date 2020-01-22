use futures::future;
use std::io;
use std::io::BufReader;
use std::net::ToSocketAddrs;
use std::path::PathBuf;
use structopt::StructOpt;
use tokio::io::{split, AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::runtime;
use tokio_rustls::{rustls::ClientConfig, webpki::DNSNameRef, TlsConnector};

use failure::Error;

enum State {
	Login(String, String),
	WaitAuthenticated,
	SelectFolder(String),
	WaitSelected,
	Idle,
}

fn main() -> Result<(), Error> {
	let opt = Options::from_args();

	let dnsname = opt.host.split(":").next();
	let host = opt
		.host
		.to_socket_addrs()?
		.next()
		.ok_or_else(|| std::io::Error::from(std::io::ErrorKind::NotFound))?;

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

	let fut = async {
		let stream = TcpStream::connect(host).await?;

		let domain = DNSNameRef::try_from_ascii_str(
			dnsname
				.ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid dnsname"))?,
		)
		.map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid dnsname"))?;

		let mut stream = connector.connect(domain, stream).await?;
		stream
			.write_all(format!(". LOGIN \"{}\" \"{}\"\r\n", opt.user, opt.pass).as_bytes())
			.await?;

		let running = true;
		let mut next: Option<String> = None;
		while running {
			let mut buff = std::vec::Vec::with_capacity(1024 * 1024);
			buff.resize(128, 0);

			if next.is_some() {
				let (mut reader, mut writer) = split(stream);
				future::select(
					reader.read(&mut buff),
					writer.write(next.unwrap().as_bytes()),
				)
				.await
				.factor_first()
				.0?;
				next = None;
				stream = reader.unsplit(writer);
			} else {
				stream.read(&mut buff).await?;
			}
			let all_lines = String::from_utf8(buff).unwrap();
			let lines = all_lines.split("\r\n").filter(|e| e.len() != 0);

			for line in lines {
				println!("-> {}", line.replace("\r\n", ""));

				if line.starts_with(". NO [AUTHENTICATIONFAILED]") {
					println!("Authentication failed, quitting");
					stream.write_all(". CLOSE\r\n".as_bytes()).await?;
				}
				if line.starts_with(". BAD") {
					println!("Sent an invalid command.");
					stream.write_all(". CLOSE\r\n".as_bytes()).await?;
				}

				if line.starts_with("* BYE") {
					println!("Remote said goodbye.");
					return Ok(());
				}

				if line.contains("Logged in") {
					println!("Logged in");

					next = Some(format!(". select {}\r\n", opt.folder));
				}

				if line.contains("Select completed") {
					next = Some(". idle\r\n".to_owned());
				}

				if line.contains(" FETCH(FLAGS") {
					let output = call_command(
						&opt.script,
						vec!["FLAGS", &opt.user, &get_flags(line)?.unwrap()],
					)?;

					println!("STDOUT: {}\nSTDERR: {}", output.0, output.1);
				}

				if line.contains(" EXISTS") {
					let output = call_command(&opt.script, vec!["EXISTS", &opt.user])?;

					println!("STDOUT: {}\nSTDERR: {}", output.0, output.1);
				}
			}
		}

		Ok(())
	};

	runtime.block_on(fut)
}

#[derive(Debug, StructOpt)]
#[structopt(name = "imap-notifier", about = "Runs a script when an email arrives.")]
struct Options {
	// host of imap server
	host: String,

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

/*
->
-> * 64 EXISTS
->
-> * 63 FETCH (FLAGS (\Seen))
->
-> * 63 FETCH (FLAGS (\Flagged \Seen))
->
-> * 59 FETCH (FLAGS (\Seen))
->
-> * 59 FETCH (FLAGS (\Answered \Seen))
-> * 65 EXISTS
->
-> * OK Still here
*/

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

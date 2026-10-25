use clap::Parser;
use serde::Deserialize;
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;

/// Структура конфигурации из TOML
#[derive(Debug, Deserialize)]
struct Config {
    protocols: Vec<Protocol>,
}

#[derive(Debug, Deserialize, Clone)]
struct Protocol {
    name: String,
    version: String,
    host: String,
    port: u16,
}

/// Аргументы командной строки
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Путь к конфигурационному файлу
    #[arg(short = 'c', long = "config", default_value = "./utnp-config.toml")]
    config: String,
}

fn main() -> std::io::Result<()> {
    let args = Args::parse();

    // Загружаем конфигурацию
    let config_content = fs::read_to_string(&args.config)
        .expect("Failed to read config file");
    let config: Config = toml::from_str(&config_content)
        .expect("Failed to parse TOML config");

    // Разделяем протоколы между потоками через Arc
    let protocols = Arc::new(config.protocols);

    let listener = TcpListener::bind("0.0.0.0:34")?;
    println!("UTNP server listening on port 34");
    println!("Loaded {} protocols", protocols.len());

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let protocols = Arc::clone(&protocols);
                thread::spawn(move || handle_client(stream, &protocols));
            }
            Err(e) => eprintln!("Connection failed: {}", e),
        }
    }
    Ok(())
}

fn handle_client(mut stream: TcpStream, protocols: &[Protocol]) {
    let mut reader = BufReader::new(&mut stream);

    let mut request_line = String::new();
    if let Err(e) = reader.read_line(&mut request_line) {
        eprintln!("Read error: {}", e);
        return;
    }
    let request_line = request_line.trim();

    // Проверяем версию UTNP
    if !request_line.starts_with("UTNP/1.0") {
        let _ = stream.write_all(
            b"UTNP ERROR - UNSUPPORTED UTNP VERSION, SUPPORTED UTNP/1.0\n",
        );
        return;
    }

    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() < 2 {
        send_error(&mut stream, "Invalid request");
        return;
    }

    let command = parts[1];
    match command {
        "LIST" => {
            send_available(&mut stream, protocols);
        }
        "NEGOTIATE" => {
            if parts.len() < 3 {
                send_error(&mut stream, "Invalid request");
                return;
            }
            let proto_list = parts[2];
            let requested: Vec<&str> = proto_list.split(',').collect();
            negotiate(&mut stream, &requested, protocols);
        }
        _ => {
            send_error(&mut stream, "Invalid request");
        }
    }
}

fn negotiate(stream: &mut TcpStream, requested: &[&str], protocols: &[Protocol]) {
    // Ищем первый поддерживаемый
    for name in requested {
        if let Some(proto) = protocols.iter().find(|p| p.name == *name) {
            let response = format!(
                "UTNP/1.0 START PROTOCOL {} {} {} {}\n",
                proto.name, proto.version, proto.host, proto.port
            );
            let _ = stream.write_all(response.as_bytes());
            return;
        }
    }

    // Не поддерживается
    let _ = stream.write_all(b"UTNP/1.0 ERROR Unsupported protocol\n");
    send_available(stream, protocols);
}

fn send_available(stream: &mut TcpStream, protocols: &[Protocol]) {
    let _ = stream.write_all(b"UTNP/1.0 AVAILABLE\n");
    for proto in protocols {
        let line = format!("{} {} {} {}\n", proto.name, proto.version, proto.host, proto.port);
        let _ = stream.write_all(line.as_bytes());
    }
}

fn send_error(stream: &mut TcpStream, msg: &str) {
    let response = format!("UTNP/1.0 ERROR {}\n", msg);
    let _ = stream.write_all(response.as_bytes());
}
use clap::Parser;
use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::time::Duration;

/// Простой клиент для UTNP (Universal Text Negotiation Protocol)
#[derive(Parser, Debug)]
#[command(author, version, about = "UTNP test client")]
struct Args {
    /// Хост UTNP-сервера
    #[arg(short = 'H', long = "host", default_value = "localhost")]
    host: String,

    /// Порт UTNP-сервера
    #[arg(short = 'p', long = "port", default_value = "34")]
    port: u16,

    /// Команда: list или negotiate <proto1,proto2,...>
    #[arg(required = true)]
    command: String,

    /// Список протоколов для negotiate (разделённые запятыми)
    #[arg(required = false)]
    protocols: Option<String>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    let address = format!("{}:{}", args.host, args.port);
    let mut stream = TcpStream::connect(address)?;
    stream.set_read_timeout(Some(Duration::from_secs(30)))?;
    stream.set_write_timeout(Some(Duration::from_secs(30)))?;

    // Формируем запрос
    let request = build_request(&args.command, &args.protocols);
    println!("→ {}", request.trim());
    stream.write_all(request.as_bytes())?;
    stream.flush()?;

    // Читаем ответ (может быть несколько строк)
    let mut reader = BufReader::new(stream);
    let mut response_lines = Vec::new();
    let mut line = String::new();

    // Читаем, пока есть данные
    loop {
        line.clear();
        match reader.read_line(&mut line) {
            Ok(0) => break, // EOF
            Ok(_) => {
                let trimmed = line.trim_end();
                if !trimmed.is_empty() {
                    response_lines.push(trimmed.to_string());
                    // Если ответ — ошибка версии UTNP, дальше ничего не будет
                    if trimmed.starts_with("UTNP ERROR") {
                        break;
                    }
                    // Если команда LIST или ответ START PROTOCOL, за ним может быть ещё что-то?
                    // В спецификации после START PROTOCOL больше нет строк, только закрытие.
                    // Для AVAILABLE — несколько строк, поэтому продолжаем читать, пока поток не закроется.
                    // Но если сервер сразу закрывает соединение, мы получим EOF на следующей итерации.
                }
            }
            Err(_e) => {
                // Если таймаут или другая ошибка, возможно, сервер закрыл соединение.
                // Если уже есть прочитанные строки, выводим их.
                break;
            }
        }
    }

    // Выводим ответ
    for line in response_lines {
        println!("← {}", line);
    }

    Ok(())
}

fn build_request(command: &str, protocols: &Option<String>) -> String {
    match command.to_lowercase().as_str() {
        "list" => format!("UTNP/1.0 LIST\n"),
        "negotiate" => {
            if let Some(prots) = protocols {
                format!("UTNP/1.0 NEGOTIATE {}\n", prots)
            } else {
                panic!("negotiate requires protocols argument (comma-separated)");
            }
        }
        _ => panic!("Unknown command: {}. Use 'list' or 'negotiate'", command),
    }
}
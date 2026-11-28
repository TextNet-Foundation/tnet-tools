use clap::{Parser, Subcommand};
use std::path::PathBuf;

/// Клиент Universal Text Negotiation Protocol.
#[derive(Parser, Debug)]
#[command(author, version, about = "UTNP client")]
pub struct Args {
	/// Хост UTNP-сервера.
	#[arg(short = 'H', long, default_value = "localhost", global = true)]
	pub host: String,

	/// Порт UTNP-сервера.
	#[arg(short = 'p', long, default_value = "34", global = true)]
	pub port: u16,

	/// Использовать устаревшую версию UTNP/1.0.
	#[arg(long, global = true)]
	pub v1: bool,

	/// Использовать SSH вместо TLS.
	#[arg(short = 's', long, global = true)]
	pub ssh: bool,

	/// Дополнительный доверенный CA-сертификат в PEM.
	#[arg(long, global = true)]
	pub ca_cert: Option<PathBuf>,

	/// Имя хоста для TLS SNI и проверки сертификата.
	/// По умолчанию используется --host.
	#[arg(long, global = true)]
	pub verify_for_sni: Option<String>,

	/// Разрешить откат на незашифрованный TCP, если SSH/TLS установить не
	/// удалось. Без флага это ошибка. --v1 по-прежнему явно выбирает TCP.
	#[arg(long = "allow-insecure-fallback", global = true)]
	pub allow_insecure_fallback: bool,

	/// Таймаут подключения и рукопожатия, секунды.
	#[arg(long, default_value_t = 15, global = true)]
	pub timeout: u64,

	#[command(subcommand)]
	pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
	/// Получить список доступных протоколов.
	List,

	/// Получить список известных UTNP-узлов.
	Explore,

	/// Согласовать версию и endpoint протокола.
	Negotiate {
		/// Имя протокола, например tmutp или tbip.
		protocol: String,

		/// Поддерживаемые версии протокола.
		/// Если не указано, сервер использует default-version.
		#[arg(long)]
		versions: Option<String>,
	},
}

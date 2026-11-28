//! Общая сетевая обвязка серверов: определение транспорта, accept-цикл с лимитами,
//! таймауты ввода-вывода и жёсткие настройки SSH.

mod io;
mod serve;
mod sniff;

pub use io::*;
pub use serve::*;
pub use sniff::*;

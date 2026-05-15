use std::fs;

fn read_config(path: &str) -> Result<String, String> {
    match fs::read_to_string(path) {
        Ok(content) => Ok(content),
        Err(e)      => Err(format!("Could not read {}: {}", path, e)),
    }
}

fn main() {
    match read_config("config.txt") {
        Ok(content) => println!("File contents: {}", content),
        Err(e)      => println!("Error: {}", e),
    }
}
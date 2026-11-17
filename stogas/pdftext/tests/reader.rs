//! Runs the built program, so that the release build tests the binary that the image holds.

use std::io::Write;
use std::process::{Command, Stdio};

/// A PDF with one page for each text.
fn pdf(pages: &[&str]) -> Vec<u8> {
    let mut objects = vec![
        "<< /Type /Catalog /Pages 2 0 R >>".to_string(),
        format!(
            "<< /Type /Pages /Count {} /Kids [{}] >>",
            pages.len(),
            (0..pages.len()).map(|page| format!("{} 0 R", 4 + 2 * page)).collect::<Vec<_>>().join(" ")
        ),
        "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>".to_string(),
    ];
    for (page, text) in pages.iter().enumerate() {
        let content = if text.is_empty() { String::new() } else { format!("BT /F1 12 Tf 72 720 Td ({text}) Tj ET") };
        objects.push(format!(
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 3 0 R >> >> /Contents {} 0 R >>",
            5 + 2 * page
        ));
        objects.push(format!("<< /Length {} >>\nstream\n{content}\nendstream", content.len()));
    }
    file_of(&objects)
}

/// A PDF file of these objects, the first of which is the catalog.
fn file_of(objects: &[String]) -> Vec<u8> {
    let mut file = b"%PDF-1.4\n".to_vec();
    let mut offsets = Vec::new();
    for (index, object) in objects.iter().enumerate() {
        offsets.push(file.len());
        file.extend(format!("{} 0 obj\n{object}\nendobj\n", index + 1).bytes());
    }
    let start = file.len();
    file.extend(format!("xref\n0 {}\n0000000000 65535 f \n", objects.len() + 1).bytes());
    for offset in offsets {
        file.extend(format!("{offset:010} 00000 n \n").bytes());
    }
    file.extend(format!("trailer\n<< /Size {} /Root 1 0 R >>\nstartxref\n{start}\n%%EOF\n", objects.len() + 1).bytes());
    file
}

/// Returns the exit status and the pages that the program wrote.
fn read(arguments: &[&str], file: &[u8]) -> (i32, Vec<String>) {
    let mut reader = Command::new(env!("CARGO_BIN_EXE_stogas-pdftext"))
        .args(arguments)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    // The program may end before it has read everything, which closes the pipe.
    let _ = reader.stdin.take().unwrap().write_all(file);
    let output = reader.wait_with_output().unwrap();
    let (mut pages, mut rest) = (Vec::new(), &output.stdout[..]);
    while rest.len() >= 4 {
        let length = u32::from_le_bytes(rest[..4].try_into().unwrap()) as usize;
        pages.push(String::from_utf8(rest[4..4 + length].to_vec()).unwrap());
        rest = &rest[4 + length..];
    }
    assert!(rest.is_empty(), "the output ends inside a page");
    (output.status.code().unwrap_or(-1), pages)
}

const LIMITS: [&str; 4] = ["2000", "8388608", "1073741824", "20"];

#[test]
fn writes_each_page_under_the_filter() {
    let (status, pages) = read(&LIMITS, &pdf(&["Invoice 4471", "", "Total: 12"]));
    assert_eq!(status, 0);
    assert_eq!(pages.iter().map(|page| page.trim()).collect::<Vec<_>>(), ["Invoice 4471", "", "Total: 12"]);
}

#[test]
fn reports_how_reading_ended() {
    assert_eq!(read(&LIMITS, b"%PDF-1.7\nnothing to parse").0, 1);
    assert_eq!(read(&["2", "8388608", "1073741824", "20"], &pdf(&["a", "b", "c"])).0, 2);
    assert_eq!(read(&["2000", "4", "1073741824", "20"], &pdf(&["more than four bytes"])).0, 3);
    // Without every limit the program reads nothing.
    assert_eq!(read(&["2000", "8388608"], &pdf(&["a"])), (6, vec![]));
}

#[test]
fn ends_when_memory_runs_out() {
    // 48 MiB of address space hold the program but not a 64 MiB file.
    let file = [pdf(&["a"]), vec![b' '; 64 << 20]].concat();
    assert_eq!(read(&["2000", "8388608", "50331648", "20"], &file).0, 5);
}

#[test]
fn ends_at_the_processor_limit_with_its_own_signal() {
    use std::os::unix::process::ExitStatusExt;
    // 500 pages share one page program of a million strings without text, which takes far more
    // than the one second of processor time that this reader gets.
    let program = format!("BT /F1 12 Tf {}ET", "() Tj ".repeat(1_000_000));
    let mut objects = vec![
        "<< /Type /Catalog /Pages 2 0 R >>".to_string(),
        format!(
            "<< /Type /Pages /Count 500 /Kids [{}] >>",
            (0..500).map(|page| format!("{} 0 R", 5 + page)).collect::<Vec<_>>().join(" ")
        ),
        "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>".to_string(),
        format!("<< /Length {} >>\nstream\n{program}\nendstream", program.len()),
    ];
    for _ in 0..500 {
        objects.push(
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 3 0 R >> >> /Contents 4 0 R >>".to_string(),
        );
    }
    let mut reader = Command::new(env!("CARGO_BIN_EXE_stogas-pdftext"))
        .args(["2000", "8388608", "1073741824", "1"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let _ = reader.stdin.take().unwrap().write_all(&file_of(&objects));
    assert_eq!(reader.wait().unwrap().signal(), Some(libc::SIGXCPU));
}

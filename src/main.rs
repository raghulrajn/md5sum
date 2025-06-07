use clap::Parser;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short, long, conflicts_with = "file")]
    string: Option<String>,
    
    #[arg(short, long, value_name = "FILE", conflicts_with = "string")]
    file: Option<std::path::PathBuf>,
}
struct Digest([[u8; 4]; 4]);

const SHIFTS:[u32;64] = [
7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,
5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,
4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,
6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21];

const K: [u32; 64] = [
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
    0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
    0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
    0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
    0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
    0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
    0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
    0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
    0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
];


impl AsRef<[[u8; 4];4]> for Digest {
    fn as_ref(&self) -> &[[u8; 4];4] {
        &self.0
    }
}

impl std::fmt::Display for Digest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for item in self.as_ref().concat().iter().map(|b| format!("{b:02x}")){
            write!(f, "{item}")?
        }
        Ok(())
    }
}
fn pre_process(last_chunk: &[u8], original_bit_length: u64) -> Vec<u8> {
    let mut padded = last_chunk.to_vec();
    padded.push(0x80); // Append a single '1' bit
    while padded.len() % 64 != 56 { // Pad until length ≡ 56 mod 64
        padded.push(0x00);
    }
    padded.extend_from_slice(&original_bit_length.to_le_bytes()); // Append length
    padded
}

fn process_chunk(chunk: &[u8], a0: &mut u32, b0: &mut u32, c0: &mut u32, d0: &mut u32) {
    let mut w: [u32; 16] = [0; 16];
    for (i, chunk) in chunk.chunks(4).enumerate() {
        w[i] = u32::from_le_bytes(chunk.try_into().unwrap());
    }

    let mut a = *a0;
    let mut b = *b0;
    let mut c = *c0;
    let mut d = *d0;

    for i in 0..64 {
        let (f, g) = match i {
            0..=15 => ((b & c) | (!b & d), i),
            16..=31 => ((d & b) | (!d & c), (5 * i + 1) % 16),
            32..=47 => (b ^ c ^ d, (3 * i + 5) % 16),
            _ => (c ^ (b | !d), (7 * i) % 16),
        };

        let temp = f.wrapping_add(a).wrapping_add(K[i]).wrapping_add(w[g]);
        a = d;
        d = c;
        c = b;
        b = b.wrapping_add(temp.rotate_left(SHIFTS[i]));
    }

    *a0 = a0.wrapping_add(a);
    *b0 = b0.wrapping_add(b);
    *c0 = c0.wrapping_add(c);
    *d0 = d0.wrapping_add(d);
}

fn compute_md5<T>(mut reader: T) -> Digest where T: std::io::Read {
    let mut a0: u32 = 0x67452301; // A
    let mut b0: u32 = 0xefcdab89; // B
    let mut c0: u32 = 0x98badcfe; // C
    let mut d0: u32 = 0x10325476; // D

    let mut buffer = [0u8; 64];
    let mut total_bytes = 0u64;
    let mut remainder = Vec::new();

    loop {
        let bytes_read = reader.read(&mut buffer).expect("Failed to read from input");
        if bytes_read == 0 {
            break; // EOF
        }
        total_bytes += bytes_read as u64;

        if bytes_read == 64 {
            process_chunk(&buffer, &mut a0, &mut b0, &mut c0, &mut d0);
        } else {
            remainder.extend_from_slice(&buffer[..bytes_read]);
            break;
        }
    }
    let padded = pre_process(&remainder, total_bytes * 8);
    for chunk in padded.chunks(64) {
        process_chunk(chunk, &mut a0, &mut b0, &mut c0, &mut d0);
    }

    Digest([
        a0.to_le_bytes(),
        b0.to_le_bytes(),
        c0.to_le_bytes(),
        d0.to_le_bytes(),
    ])
}
fn main() {
    let args = Args::parse();
    let digest = if let Some(s) = args.string {
        compute_md5(s.as_bytes())
    } else if let Some(path) = args.file {
        let file = std::fs::File::open(path).expect("Failed to open file");
        let reader = std::io::BufReader::new(file);
        compute_md5(reader)
    } else {
        eprintln!("Either --string or --file must be provided.");
        std::process::exit(1);
    };
    println!("{digest}");
}

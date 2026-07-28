use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use solana_program_fingerprint::{
    cluster, compare_files, fingerprint_db, fingerprint_file, lsh_index, similarity_report,
    minhash::DEFAULT_NUM_HASHES, opcode_ngram::DEFAULT_NGRAM_SIZE,
};

#[derive(Parser)]
#[command(
    name = "solana_program_fingerprint",
    about = "Bytecode similarity engine for Solana programs",
    author = "Soubhagya",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Compare similarity between two program binaries
    Compare {
        file_a: PathBuf,
        file_b: PathBuf,
    },
    /// Print fingerprint for a single program binary
    Fingerprint {
        file: PathBuf,
    },
    /// Cluster program binaries in a directory by similarity
    Cluster {
        dir: PathBuf,
        /// Jaccard similarity threshold for grouping (0.0 to 1.0)
        #[arg(long, default_value_t = 0.5)]
        threshold: f64,
    },
    /// Build fingerprint catalog from a directory
    Index {
        dir: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Query catalog for similar programs
    Query {
        file: PathBuf,
        #[arg(long)]
        db: PathBuf,
        #[arg(long, default_value_t = 0.6)]
        min_jaccard: f64,
    },
    /// Detailed similarity report between two programs
    Report {
        file_a: PathBuf,
        file_b: PathBuf,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.command {
        Commands::Compare { file_a, file_b } => cmd_compare(&file_a, &file_b),
        Commands::Fingerprint { file } => cmd_fingerprint(&file),
        Commands::Cluster { dir, threshold } => cmd_cluster(&dir, threshold),
        Commands::Index { dir, output } => cmd_index(&dir, &output),
        Commands::Query {
            file,
            db,
            min_jaccard,
        } => cmd_query(&file, &db, min_jaccard),
        Commands::Report { file_a, file_b } => cmd_report(&file_a, &file_b),
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(msg) => {
            eprintln!("error: {msg}");
            ExitCode::FAILURE
        }
    }
}

fn cmd_compare(file_a: &PathBuf, file_b: &PathBuf) -> Result<(), String> {
    let result = compare_files(file_a, file_b)?;
    println!("file_a: {}", file_a.display());
    println!("file_b: {}", file_b.display());
    println!("jaccard_estimate: {:.4}", result.jaccard_estimate);
    println!("jaccard_exact:    {:.4}", result.jaccard_exact);
    println!("simhash_similarity: {:.4}", result.simhash_similarity);
    println!("hamming_distance: {}", result.hamming_distance);
    Ok(())
}

fn cmd_fingerprint(file: &PathBuf) -> Result<(), String> {
    let fp = fingerprint_file(file)?;
    println!("file: {}", file.display());
    println!("ngram_count: {}", fp.ngram_count);
    println!("simhash: {:016x}", fp.simhash.0);
    println!("minhash_signature:");
    for (i, val) in fp.minhash.values.iter().enumerate() {
        if i > 0 && i % 4 == 0 {
            println!();
        }
        print!(" {:016x}", val);
    }
    println!();
    Ok(())
}

fn cmd_cluster(dir: &PathBuf, threshold: f64) -> Result<(), String> {
    let result = cluster::cluster_directory(dir, threshold, DEFAULT_NGRAM_SIZE, DEFAULT_NUM_HASHES)?;
    println!("directory: {}", dir.display());
    println!("threshold: {:.2}", threshold);
    println!("clusters: {}", result.clusters.len());
    println!();

    for cluster in &result.clusters {
        println!(
            "cluster {} ({} members, avg_similarity {:.4})",
            cluster.id,
            cluster.members.len(),
            cluster.avg_similarity
        );
        for member in &cluster.members {
            println!("  {}", member.display());
        }
        println!();
    }
    Ok(())
}

fn cmd_index(dir: &PathBuf, output: &PathBuf) -> Result<(), String> {
    let db = fingerprint_db::FingerprintDb::scan_directory(dir, DEFAULT_NGRAM_SIZE, DEFAULT_NUM_HASHES)?;
    db.save(output)?;
    println!("indexed {} programs", db.len());
    println!("catalog: {}", output.display());
    Ok(())
}

fn cmd_query(file: &PathBuf, db_path: &PathBuf, min_jaccard: f64) -> Result<(), String> {
    let db = fingerprint_db::FingerprintDb::load(db_path)?;
    let fp = fingerprint_file(file)?;
    let index = lsh_index::build_index_from_db(&db, 8)?;
    let hits = index.query_with_scores(&fp.minhash, min_jaccard);

    println!("query: {}", file.display());
    println!("catalog: {} entries", db.len());
    for (program_id, jaccard) in hits {
        println!("  {} jaccard={:.4}", program_id, jaccard);
    }
    Ok(())
}

fn cmd_report(file_a: &PathBuf, file_b: &PathBuf) -> Result<(), String> {
    let report = similarity_report::compare_paths(file_a, file_b)?;
    println!("{}", similarity_report::format_report(&report));
    Ok(())
}

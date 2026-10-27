#!/usr/bin/env python3
"""Compare BN128 execute() in isolated runtimes, alternating both versions within each JVM."""

import argparse
import csv
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import statistics
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[2]
FP2 = "crypto/src/main/java/org/tron/common/crypto/zksnark/Fp2.java"
BENCHMARK = "org.tron.common.runtime.vm.Bn128PrecompileBenchmark"
CASES = {"addition", "multiplication", "pairing-1", "pairing-2", "pairing-4"}
JVM_FLAGS = ["-Xms512m", "-Xmx512m", "-XX:+UseParallelGC", "-Xbatch",
             "-Dconsole.log.level=INFO"]


def command(args, **kwargs):
    return subprocess.run(args, cwd=ROOT, check=True, text=True, **kwargs)


def capture(args):
    return command(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT).stdout.strip()


def summarize(medians):
    results = {}
    for name in sorted(CASES):
        before = [ns for variant, _, case, ns, _ in medians
                  if variant == "baseline" and case == name]
        after = [ns for variant, _, case, ns, _ in medians
                 if variant == "optimized" and case == name]
        paired = [100 * (a - b) / a for a, b in zip(before, after)]
        allocated = {
            variant: statistics.median([size for label, _, case, _, size in medians
                                        if label == variant and case == name])
            for variant in ("baseline", "optimized")
        }
        results[name] = {
            "marginal_median_latency_ns": {"baseline": statistics.median(before),
                                           "optimized": statistics.median(after)},
            "paired_latency_reduction_percent": {"median": statistics.median(paired),
                                                  "min": min(paired), "max": max(paired),
                                                  "per_fork": paired},
            "paired_speedup_median": statistics.median([a / b for a, b in zip(before, after)]),
            "fork_median_latency_ns": {"baseline": before, "optimized": after},
            "median_allocated_bytes_per_op": allocated,
        }
        print("%s: paired median latency reduction %.2f%%; %.3fx" %
              (name, statistics.median(paired), results[name]["paired_speedup_median"]))
    return results


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", default="release_v4.8.3")
    parser.add_argument("--forks", type=int, default=5, help="fresh JVMs with both variants (minimum 3)")
    parser.add_argument("--rounds", type=int, default=7, help="measurement rounds per case")
    parser.add_argument("--output", type=Path,
                        default=ROOT / "framework/build/reports/bn128-fp2")
    args = parser.parse_args()
    if args.forks < 3 or args.rounds < 3 or args.rounds % 2 == 0:
        parser.error("use at least 3 forks and an odd number of rounds >= 3")
    for name in ("JAVA_TOOL_OPTIONS", "JDK_JAVA_OPTIONS", "_JAVA_OPTIONS"):
        if "javaagent" in os.environ.get(name, ""):
            parser.error("remove coverage/profiling agents before benchmarking")

    baseline = capture(["git", "rev-parse", "--verify", args.baseline + "^{commit}"])
    changed = capture(["git", "diff", "--name-only", baseline, "--",
                       ":(glob)**/src/main/**"]).splitlines()
    if changed != [FP2]:
        parser.error("runtime source changes must be limited to Fp2.java for this comparison")
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    baseline_source = capture(["git", "show", baseline + ":" + FP2]) + "\n"
    metadata = {
        "baseline_commit": baseline,
        "head_commit": capture(["git", "rev-parse", "HEAD"]),
        "branch": capture(["git", "branch", "--show-current"]),
        "java": capture(["java", "-version"]),
        "platform": platform.platform(),
        "processor": platform.processor(),
        "logical_cpus": os.cpu_count(),
        "jvm_flags": JVM_FLAGS,
        "forks_per_variant": args.forks,
        "rounds_per_case": args.rounds,
        "baseline_source_sha256": hashlib.sha256(baseline_source.encode()).hexdigest(),
        "optimized_source_sha256": hashlib.sha256((ROOT / FP2).read_bytes()).hexdigest(),
        "measurement": "PrecompiledContract.execute; no VM/database/transaction processing",
        "isolation": "separate URLClassLoaders in each JVM; baseline Fp2.class is prepended; "
                     "otherwise identical classpaths; versions alternate each measurement round",
    }
    if platform.system() == "Darwin":
        metadata["cpu_model"] = capture(["sysctl", "-n", "machdep.cpu.brand_string"])
        metadata["memory_bytes"] = int(capture(["sysctl", "-n", "hw.memsize"]))
    (output / "metadata.json").write_text(json.dumps(metadata, indent=2) + "\n")
    (output / "fp2.patch").write_text(capture(["git", "diff", baseline, "--", FP2]) + "\n")

    with tempfile.TemporaryDirectory(prefix="bn128-benchmark-") as scratch_name:
        scratch = Path(scratch_name)
        init = scratch / "benchmark.init.gradle"
        init.write_text("""gradle.projectsEvaluated {
    def frameworkProject = rootProject.project(':framework')
    frameworkProject.tasks.register('writeBn128BenchmarkClasspath') {
        dependsOn frameworkProject.tasks.named('testClasses')
        doLast {
            new File(System.getenv('BN128_BENCHMARK_CLASSPATH')).text =
                    frameworkProject.sourceSets.test.runtimeClasspath.asPath
        }
    }
}
""")
        classpath_file = scratch / "classpath.txt"
        env = dict(os.environ, BN128_BENCHMARK_CLASSPATH=str(classpath_file))
        command(["./gradlew", ":framework:writeBn128BenchmarkClasspath", "-I", str(init),
                 "--console=plain"], env=env)
        classpath = classpath_file.read_text().strip()
        source = scratch / "Fp2.java"
        source.write_text(baseline_source)
        baseline_classes = scratch / "baseline"
        baseline_classes.mkdir()
        command(["javac", "-proc:none", "-cp", classpath, "-d", str(baseline_classes),
                 str(source)])
        baseline_classpath = str(baseline_classes) + os.pathsep + classpath

        # Run the same independent arithmetic and precompile regression tests on both variants.
        for variant, cp in (("baseline", baseline_classpath), ("optimized", classpath)):
            with (output / (variant + "-verification.log")).open("w") as log:
                command(["java"] + JVM_FLAGS + ["-cp", cp, "org.junit.runner.JUnitCore",
                        "org.tron.common.crypto.zksnark.Fp2Test",
                        "org.tron.common.runtime.vm.Bn128PrecompileTest"],
                        stdout=log, stderr=subprocess.STDOUT)

        rows = []
        medians = []
        corpus = None
        for fork in range(args.forks):
            log_path = output / ("paired-%d.log" % (fork + 1))
            print("Running paired fork %d/%d" % (fork + 1, args.forks), flush=True)
            with log_path.open("w") as log:
                command(["java"] + JVM_FLAGS + ["-DrunPrecompileBenchmark=true",
                        "-Dbn128BenchmarkRounds=" + str(args.rounds),
                        "-Dbn128BenchmarkFork=" + str(fork),
                        "-Dbn128BaselineClasspath=" + baseline_classpath, "-cp", classpath,
                        "org.junit.runner.JUnitCore", BENCHMARK],
                        stdout=log, stderr=subprocess.STDOUT)
            text = log_path.read_text()
            for variant in ("baseline", "optimized"):
                hashes = dict(re.findall(r"BN128_CORPUS," + variant
                                         + r",([\w-]+),([0-9a-f]+)", text))
                if set(hashes) != CASES or (corpus is not None and hashes != corpus):
                    raise RuntimeError("benchmark input/output corpus differs: " + str(log_path))
                corpus = hashes
            if str(baseline_classes) not in text:
                raise RuntimeError("baseline Fp2 override was not loaded")
            samples = re.findall(
                r"BN128_ROUND,(baseline|optimized),([\w-]+),(\d+),(\d+),([\d.]+),(-?[\d.]+)",
                text)
            summaries = re.findall(
                r"BN128_MEDIAN,(baseline|optimized),([\w-]+),([\d.]+),(-?[\d.]+)", text)
            if len(samples) != 2 * len(CASES) * args.rounds or len(summaries) != 2 * len(CASES):
                raise RuntimeError("incomplete benchmark results: " + str(log_path))
            rows.extend((variant, fork + 1, *sample) for variant, *sample in samples)
            medians.extend((variant, fork + 1, name, float(ns), float(allocated))
                           for variant, name, ns, allocated in summaries)
            print("Completed paired fork %d" % (fork + 1), flush=True)

    with (output / "rounds.csv").open("w", newline="") as file:
        writer = csv.writer(file)
        writer.writerow(["variant", "fork", "case", "round", "iterations", "ns_per_op",
                         "allocated_bytes_per_op"])
        writer.writerows(rows)
    with (output / "fork-medians.csv").open("w", newline="") as file:
        writer = csv.writer(file)
        writer.writerow(["variant", "fork", "case", "ns_per_op", "allocated_bytes_per_op"])
        writer.writerows(medians)
    results = summarize(medians)
    (output / "summary.json").write_text(json.dumps(results, indent=2) + "\n")
    (output / "corpus-sha256.json").write_text(json.dumps(corpus, indent=2) + "\n")
    print("Evidence: " + str(output))


if __name__ == "__main__":
    main()

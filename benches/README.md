### Run all benchmarks

```
cargo bench
```

### Review flamegraph for a specific benchmark set

```
cargo bench --bench <name_of_file> -- --profile-time=20
find . -iname "*flame*.svg"
```

E.g. `<name_of_file>` == `bench_2_fmt`

### Troubleshooting if flamegraphs don't work

```
echo -1 | sudo tee /proc/sys/kernel/perf_event_paranoid
```
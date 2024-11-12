import json
import sys

def read_json_array(filename):
    with open(filename, 'r') as file:
        data = json.load(file)
    return data

if __name__ == "__main__":
    infile = sys.argv[1]
    outfile = sys.argv[2]
    data = read_json_array(infile)

    with open(outfile, 'w') as file:
        file.write(
            """// Code generated from metrics.json. DO NOT EDIT.
// NOTE: metrics.json was copied from opentelemetry-ebpf.profiler.
// It should be kept in sync when upgrading versions.

package metrics

import (
\totelmetrics "go.opentelemetry.io/ebpf-profiler/metrics"
)

const (
\tMetricUnitNone         = 0
\tMetricUnitPercent      = 1
\tMetricUnitByte         = 2
\tMetricUnitMicroseconds = 3
\tMetricUnitMilliseconds = 4
\tMetricUnitSeconds      = 5
)

const (
\tMetricTypeGauge   = 0
\tMetricTypeCounter = 1
)

var AllMetrics = map[otelmetrics.MetricID]Metric {
""")
        def get_type(s):
            match s:
                case "gauge":
                    return "MetricTypeGauge"
                case "counter":
                    return "MetricTypeCounter"
                case _:
                    raise ValueError(f"Unknown metric type: {s}")

        def get_unit(s):
            match s:
                case None:
                    return "MetricUnitNone"
                case "percent":
                    return "MetricUnitPercent"
                case "byte":
                    return "MetricUnitByte"
                case "micros":
                    return "MetricUnitMicroseconds"
                case "ms":
                    return "MetricUnitMilliseconds"
                case "s":
                    return "MetricUnitSeconds"
                case _:
                    raise ValueError(f"Unknown metric unit: {s}")

        for metric in data:
            if not "name" in metric:
                continue
            if not "field" in metric:
                continue
            if metric.get("obsolete"):
                continue
            file.write(f"""\totelmetrics.ID{metric["name"]}: {{
\t\tDesc:  "{metric["description"]}",
\t\tField: "{metric["field"]}",
\t\tType:  {get_type(metric.get("type"))},
\t\tUnit:  {get_unit(metric.get("unit"))},
\t}},
""")
        file.write("}\n")

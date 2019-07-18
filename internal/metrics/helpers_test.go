package metrics

import (
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"go.opencensus.io/metric/metricdata"
	"go.opencensus.io/stats/view"
)

func testDataRetrieval(v *view.View, t *testing.T, want string) {
	if v == nil {
		t.Fatalf("%s: nil view passed", t.Name())
	}
	name := v.Name
	data, err := view.RetrieveData(name)

	if err != nil {
		t.Fatalf("%s: failed to retrieve data line %s", name, err)
	}

	if want != "" && len(data) != 1 {
		t.Fatalf("%s: received incorrect number of data rows: %d", name, len(data))
	}
	if want == "" && len(data) > 0 {
		t.Fatalf("%s: received incorrect number of data rows: %d", name, len(data))
	} else if want == "" {
		return
	}

	dataString := data[0].String()

	if want != "" && !strings.HasPrefix(dataString, want) {
		t.Errorf("%s: Found unexpected data row: \nwant: %s\ngot: %s\n", name, want, dataString)
	}
}

func testMetricRetrieval(metrics []*metricdata.Metric, t *testing.T, labels []metricdata.LabelValue, value int64) {

	metric := metrics[0]
	gotLabels := metric.TimeSeries[0].LabelValues
	gotValue := metric.TimeSeries[0].Points[0].Value

	if diff := cmp.Diff(gotLabels, labels); diff != "" {
		t.Errorf("Failed to find metric labels:\n%s", diff)
	}
	if diff := cmp.Diff(gotValue, value); diff != "" {
		t.Errorf("Failed to find metric value:\n%s", diff)
	}

}

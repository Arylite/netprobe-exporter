package probe

import (
	"math"
	"testing"
	"time"
)

const ms = time.Millisecond

// A path that is steadily slow and a path that alternates have the same
// standard deviation profile only by accident; RFC 3550 jitter separates them,
// which is the whole reason for reporting it next to the standard deviation.
func TestJitter(t *testing.T) {
	steady := []time.Duration{50 * ms, 50 * ms, 50 * ms, 50 * ms}
	if j := Jitter(steady); j != 0 {
		t.Fatalf("a constant path has no jitter, got %v", j)
	}

	// Alternating 10/50 ms: every step deviates by 40 ms, and the 1/16 gain
	// converges towards it from zero, so a short cycle stays well below.
	alternating := []time.Duration{10 * ms, 50 * ms, 10 * ms, 50 * ms}
	j := Jitter(alternating)
	if j <= 0 || j >= 40*ms {
		t.Fatalf("jitter = %v, want between 0 and 40ms", j)
	}
	if Jitter(alternating[:1]) != 0 {
		t.Fatal("a single sample cannot show a deviation")
	}

	// The smoothing must build up, not reset: more of the same deviation moves
	// the estimate closer to it.
	long := make([]time.Duration, 40)
	for i := range long {
		long[i] = 10 * ms
		if i%2 == 1 {
			long[i] = 50 * ms
		}
	}
	if Jitter(long) <= j {
		t.Fatalf("jitter should converge upwards: short=%v long=%v", j, Jitter(long))
	}
}

func TestVoiceQuality(t *testing.T) {
	// A LAN grade path scores at the top of the scale.
	perfect := VoiceQuality(2*ms, 0, 0)
	if perfect.MOS < 4.3 || perfect.MOS > 4.5 {
		t.Fatalf("perfect path: MOS = %v, want about 4.4", perfect.MOS)
	}

	// Total loss is unusable whatever the latency says.
	dead := VoiceQuality(10*ms, 0, 1)
	if dead.MOS != 1 || dead.R != 0 {
		t.Fatalf("total loss: %+v, want MOS 1 and R 0", dead)
	}

	// Each of the three inputs must degrade the score on its own.
	base := VoiceQuality(40*ms, 2*ms, 0)
	for name, worse := range map[string]Quality{
		"latency": VoiceQuality(400*ms, 2*ms, 0),
		"jitter":  VoiceQuality(40*ms, 60*ms, 0),
		"loss":    VoiceQuality(40*ms, 2*ms, 0.05),
	} {
		if worse.MOS >= base.MOS {
			t.Errorf("%s: MOS %v did not drop below the baseline %v", name, worse.MOS, base.MOS)
		}
	}

	// The scale is bounded at both ends whatever it is fed.
	for _, q := range []Quality{perfect, dead, base, VoiceQuality(9*time.Second, time.Second, 0.9)} {
		if q.MOS < 1 || q.MOS > 4.5 || q.R < 0 || q.R > 100 || math.IsNaN(q.MOS) {
			t.Errorf("out of range: %+v", q)
		}
	}
}

package probe

import (
	"math"
	"time"
)

// Jitter returns the interarrival jitter of RFC 3550: the mean deviation
// between consecutive samples, smoothed by a 1/16 gain.
//
// This is not the same quantity as the standard deviation reported alongside
// it. The standard deviation measures how far the samples spread around their
// own mean, so a path that is steadily slow scores well and a path that
// alternates between two stable values scores badly. RFC 3550 measures the
// change from one packet to the next, which is what a jitter buffer has to
// absorb, and is the number every VoIP and streaming tool calls "jitter".
func Jitter(rtts []time.Duration) time.Duration {
	var j float64
	for i := 1; i < len(rtts); i++ {
		d := math.Abs(float64(rtts[i] - rtts[i-1]))
		j += (d - j) / 16
	}
	return time.Duration(j)
}

// Quality rates a path for interactive voice.
type Quality struct {
	R   float64 // transmission rating factor, 0 to about 93 for a perfect path
	MOS float64 // mean opinion score, 1 (unusable) to 4.5 (perfect)
}

// codecDelay stands for the packetisation and jitter-buffer delay of a typical
// G.711 endpoint, which the network measurement itself cannot see.
const codecDelay = 10 * time.Millisecond

// VoiceQuality derives an R factor and a MOS from measurements the probe
// already makes, using the simplified ITU-T G.107 E-model that VoIP monitoring
// tools converged on. It sends no extra traffic.
//
// One-way delay is approximated as half the round trip. That assumption breaks
// on an asymmetric path, which is common enough on consumer access links, so
// treat the score as an indicator rather than a measurement: it answers "can
// this line hold a call" and not "the call scored exactly 3.8".
func VoiceQuality(rtt, jit time.Duration, loss float64) Quality {
	effective := float64(rtt/2+2*jit+codecDelay) / float64(time.Millisecond)

	var r float64
	if effective < 160 {
		r = 93.2 - effective/40
	} else {
		// Past 160 ms the ear stops tolerating delay and the penalty steepens.
		r = 93.2 - (effective-120)/10
	}
	r -= loss * 100 * 2.5 // each percent of loss costs 2.5 points

	if r <= 0 {
		return Quality{R: 0, MOS: 1}
	}
	if r > 100 {
		r = 100
	}
	mos := 1 + 0.035*r + r*(r-60)*(100-r)*7.1e-6
	return Quality{R: r, MOS: math.Min(mos, 4.5)}
}

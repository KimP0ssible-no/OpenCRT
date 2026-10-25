//! Remote sound (RDPSND): the server sends its audio as plain PCM, 44.1 kHz
//! 16-bit stereo (the one format every Windows server offers, and nothing to
//! decode), and it is played on this computer: through cpal (WASAPI,
//! CoreAudio) on Windows and macOS, through ALSA loaded at run time on Linux.

use std::borrow::Cow;

use ironrdp::rdpsnd::client::RdpsndClientHandler;
use ironrdp::rdpsnd::pdu::{AudioFormat, PitchPdu, VolumePdu, WaveFormat};

/// Samples per second the server is asked for.
const RATE: u32 = 44_100;

/// The only format offered: IronRDP sends the server the formats both sides
/// have, unordered, so with one the format number of each wave is never in doubt.
const FORMATS: [AudioFormat; 1] = [AudioFormat {
    format: WaveFormat::PCM,
    n_channels: 2,
    n_samples_per_sec: RATE,
    n_avg_bytes_per_sec: RATE * 4,
    n_block_align: 4,
    bits_per_sample: 16,
    data: None,
}];

#[derive(Debug)]
pub struct Sound {
    /// Started with the first sound; None again after the server closes it.
    player: Option<player::Player>,
    /// The server's volume for the left and right channel, 0.0 to 1.0.
    volume: [f32; 2],
    /// No audio output here: stop trying.
    unavailable: bool,
    /// Sound received so far, for the connection log.
    waves: u64,
}

impl Sound {
    pub fn new() -> Self {
        Sound { player: None, volume: [1.0, 1.0], unavailable: false, waves: 0 }
    }
}

impl RdpsndClientHandler for Sound {
    fn get_formats(&self) -> &[AudioFormat] {
        crate::note(format_args!("sound: the server's formats arrived; OpenCRT takes PCM 44.1 kHz 16-bit stereo"));
        &FORMATS
    }

    fn wave(&mut self, format_no: usize, _ts: u32, data: Cow<'_, [u8]>) {
        self.waves += 1;
        if self.waves == 1 {
            crate::note(format_args!("sound: first sound from the server ({} bytes, format {format_no})", data.len()));
        }
        if self.player.is_none() && !self.unavailable {
            self.player = player::Player::start(RATE);
            self.unavailable = self.player.is_none();
            if self.unavailable {
                crate::note(format_args!("sound: no audio output could be opened here"));
            } else {
                crate::note(format_args!("sound: playing on the default output device"));
            }
        }
        if let Some(player) = &self.player {
            player.play(frames(&data, self.volume));
        }
    }

    fn set_volume(&mut self, volume: VolumePdu) {
        self.volume = [volume.volume_left, volume.volume_right].map(|v| f32::from(v) / f32::from(u16::MAX));
        crate::note(format_args!("sound: the server sets the volume to {:.0}% / {:.0}%", self.volume[0] * 100.0, self.volume[1] * 100.0));
    }

    fn set_pitch(&mut self, _: PitchPdu) {}

    fn close(&mut self) {
        crate::note(format_args!("sound: the server closed the sound ({} pieces played)", self.waves));
        self.player = None;
    }
}

/// The same sound over the dynamic channel Windows 8 and later prefer when
/// the client has dynamic channels (and then never uses the static one): the
/// same messages, without the static channel's framing, handled by the same
/// IronRDP processor.
pub struct Dynamic(ironrdp::rdpsnd::client::Rdpsnd);

ironrdp::core::impl_as_any!(Dynamic);

impl Dynamic {
    pub fn new() -> Self {
        Dynamic(ironrdp::rdpsnd::client::Rdpsnd::new(Box::new(Sound::new())))
    }
}

/// Already-encoded bytes, as a dynamic channel message.
struct Raw(Vec<u8>);

impl ironrdp::core::Encode for Raw {
    fn encode(&self, dst: &mut ironrdp::core::WriteCursor<'_>) -> ironrdp::core::EncodeResult<()> {
        ironrdp::core::ensure_size!(in: dst, size: self.0.len());
        dst.write_slice(&self.0);
        Ok(())
    }
    fn name(&self) -> &'static str {
        "RDPSND over DVC"
    }
    fn size(&self) -> usize {
        self.0.len()
    }
}

impl ironrdp::dvc::DvcEncode for Raw {}

impl ironrdp::dvc::DvcProcessor for Dynamic {
    fn channel_name(&self) -> &str {
        "AUDIO_PLAYBACK_DVC"
    }

    fn start(&mut self, _: u32) -> ironrdp::pdu::PduResult<Vec<ironrdp::dvc::DvcMessage>> {
        crate::note(format_args!("sound: the server opened the dynamic sound channel"));
        Ok(Vec::new())
    }

    fn process(&mut self, _: u32, payload: &[u8]) -> ironrdp::pdu::PduResult<Vec<ironrdp::dvc::DvcMessage>> {
        let replies = ironrdp::svc::SvcProcessor::process(&mut self.0, payload)?;
        replies
            .into_iter()
            .map(|reply| {
                let bytes = reply.encode_unframed_pdu().map_err(|e| ironrdp::pdu::encode_err!(e))?;
                Ok(Box::new(Raw(bytes)) as ironrdp::dvc::DvcMessage)
            })
            .collect()
    }
}

impl ironrdp::dvc::DvcClientProcessor for Dynamic {}

/// Little-endian 16-bit stereo PCM as frames, at `volume`.
fn frames(pcm: &[u8], volume: [f32; 2]) -> Vec<[i16; 2]> {
    let sample = |b: &[u8], v: f32| (f32::from(i16::from_le_bytes([b[0], b[1]])) * v) as i16;
    pcm.as_chunks::<4>().0.iter().map(|f| [sample(&f[0..2], volume[0]), sample(&f[2..4], volume[1])]).collect()
}

/// Turns frames at one rate into frames at another (the output device's),
/// by linear interpolation: plenty for speech and system sounds.
#[cfg_attr(not(any(windows, target_os = "macos", test)), allow(dead_code))]
struct Resample {
    /// Source frames per output frame.
    step: f64,
    /// How far between `from` and `to` the next output frame lies.
    at: f64,
    from: [f32; 2],
    to: [f32; 2],
}

#[cfg_attr(not(any(windows, target_os = "macos", test)), allow(dead_code))]
impl Resample {
    fn new(source: u32, output: u32) -> Self {
        Resample { step: f64::from(source) / f64::from(output), at: 0.0, from: [0.0; 2], to: [0.0; 2] }
    }

    /// The next output frame (-1.0 to 1.0); `pull` gives source frames, None
    /// when none are waiting (then it is silence).
    fn next(&mut self, mut pull: impl FnMut() -> Option<[i16; 2]>) -> [f32; 2] {
        while self.at >= 1.0 {
            self.at -= 1.0;
            self.from = self.to;
            self.to = pull().map_or([0.0; 2], |f| f.map(|s| f32::from(s) / 32768.0));
        }
        let t = self.at as f32;
        self.at += self.step;
        [0, 1].map(|c| self.from[c] + (self.to[c] - self.from[c]) * t)
    }
}

#[cfg(any(windows, target_os = "macos"))]
mod player {
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};

    use cpal::traits::{DeviceTrait as _, HostTrait as _, StreamTrait as _};

    use super::Resample;

    /// At most this much sound waits to be played (frames), so a stalled
    /// output never builds up a delay: the oldest is dropped.
    const MAX_QUEUED: usize = super::RATE as usize / 2;

    /// The default output device, playing what is queued. cpal's stream may
    /// not move between threads, so a thread of its own keeps it.
    #[derive(Debug)]
    pub struct Player {
        queue: Arc<Mutex<VecDeque<[i16; 2]>>>,
        _stop: std::sync::mpsc::Sender<()>,
    }

    impl Player {
        pub fn start(rate: u32) -> Option<Player> {
            let queue = Arc::new(Mutex::new(VecDeque::new()));
            let (stop, stopped) = std::sync::mpsc::channel::<()>();
            let (ready, started) = std::sync::mpsc::channel();
            let source = queue.clone();
            std::thread::spawn(move || {
                let stream = open(rate, source);
                let ok = stream.is_some();
                let _ = ready.send(ok);
                if ok {
                    let _ = stopped.recv(); // until the Player is dropped
                }
                drop(stream);
            });
            started.recv().ok().filter(|&ok| ok).map(|_| Player { queue, _stop: stop })
        }

        pub fn play(&self, frames: Vec<[i16; 2]>) {
            if let Ok(mut queue) = self.queue.lock() {
                queue.extend(frames);
                let over = queue.len().saturating_sub(MAX_QUEUED);
                queue.drain(..over);
            }
        }
    }

    fn open(rate: u32, queue: Arc<Mutex<VecDeque<[i16; 2]>>>) -> Option<cpal::Stream> {
        let device = cpal::default_host().default_output_device()?;
        let supported = device.default_output_config().ok()?;
        let config = supported.config();
        let channels = usize::from(config.channels).max(1);
        let mut resample = Resample::new(rate, config.sample_rate);
        // Fill each device frame: left and right first, other channels silent;
        // a mono device gets the mix.
        let mut fill = move |frame: &mut [f32]| {
            let [l, r] = resample.next(|| queue.lock().ok()?.pop_front());
            frame.fill(0.0);
            match frame {
                [only] => *only = (l + r) / 2.0,
                [left, right, ..] => (*left, *right) = (l, r),
                [] => {}
            }
        };
        let error = |_| {};
        let stream = match supported.sample_format() {
            cpal::SampleFormat::F32 => device.build_output_stream(
                &config,
                move |data: &mut [f32], _: &_| data.chunks_mut(channels).for_each(&mut fill),
                error,
                None,
            ),
            cpal::SampleFormat::I16 => {
                let mut frame = vec![0.0f32; channels];
                device.build_output_stream(
                    &config,
                    move |data: &mut [i16], _: &_| {
                        for out in data.chunks_mut(channels) {
                            fill(&mut frame);
                            for (o, s) in out.iter_mut().zip(&frame) {
                                *o = (s.clamp(-1.0, 1.0) * 32767.0) as i16;
                            }
                        }
                    },
                    error,
                    None,
                )
            }
            _ => return None,
        }
        .ok()?;
        stream.play().ok()?;
        Some(stream)
    }
}

#[cfg(target_os = "linux")]
mod player {
    use std::ffi::{c_char, c_int, c_long, c_uint, c_ulong, c_void};

    type Pcm = *mut c_void;
    const STREAM_PLAYBACK: c_int = 0;
    const FORMAT_S16_LE: c_int = 2;
    const ACCESS_RW_INTERLEAVED: c_int = 3;
    /// Asked of ALSA: about a tenth of a second of buffering.
    const LATENCY_US: c_uint = 100_000;

    /// The ALSA functions used, from libasound.so.2 loaded at run time: every
    /// Linux desktop has it, and the helper keeps needing only glibc.
    struct Alsa {
        open: Open,
        set_params: SetParams,
        writei: Writei,
        recover: Recover,
        close: Close,
    }
    type Open = unsafe extern "C" fn(*mut Pcm, *const c_char, c_int, c_int) -> c_int;
    type SetParams = unsafe extern "C" fn(Pcm, c_int, c_int, c_uint, c_uint, c_int, c_uint) -> c_int;
    type Writei = unsafe extern "C" fn(Pcm, *const c_void, c_ulong) -> c_long;
    type Recover = unsafe extern "C" fn(Pcm, c_int, c_int) -> c_int;
    type Close = unsafe extern "C" fn(Pcm) -> c_int;

    impl Alsa {
        fn load() -> Option<Alsa> {
            // SAFETY: dlopen/dlsym with NUL-terminated names; each symbol is cast
            // to the signature alsa/pcm.h declares for it. The library is never
            // unloaded, so the pointers stay valid.
            unsafe {
                let lib = libc::dlopen(c"libasound.so.2".as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL);
                if lib.is_null() {
                    return None;
                }
                let symbol = |name: &std::ffi::CStr| {
                    let f = libc::dlsym(lib, name.as_ptr());
                    (!f.is_null()).then_some(f)
                };
                Some(Alsa {
                    open: std::mem::transmute::<*mut c_void, Open>(symbol(c"snd_pcm_open")?),
                    set_params: std::mem::transmute::<*mut c_void, SetParams>(symbol(c"snd_pcm_set_params")?),
                    writei: std::mem::transmute::<*mut c_void, Writei>(symbol(c"snd_pcm_writei")?),
                    recover: std::mem::transmute::<*mut c_void, Recover>(symbol(c"snd_pcm_recover")?),
                    close: std::mem::transmute::<*mut c_void, Close>(symbol(c"snd_pcm_close")?),
                })
            }
        }
    }

    /// ALSA's default device, written from a thread of its own (writes block
    /// until the sound is played, which also paces it).
    #[derive(Debug)]
    pub struct Player {
        frames: std::sync::mpsc::Sender<Vec<[i16; 2]>>,
    }

    impl Player {
        pub fn start(rate: u32) -> Option<Player> {
            let alsa = Alsa::load()?;
            let mut pcm: Pcm = std::ptr::null_mut();
            // SAFETY: `pcm` receives the handle; "default" is NUL-terminated.
            let opened = unsafe { (alsa.open)(&mut pcm, c"default".as_ptr(), STREAM_PLAYBACK, 0) };
            if opened < 0 {
                return None;
            }
            // SAFETY: `pcm` was opened above. ALSA resamples to the device itself (soft_resample 1).
            if unsafe { (alsa.set_params)(pcm, FORMAT_S16_LE, ACCESS_RW_INTERLEAVED, 2, rate, 1, LATENCY_US) } < 0 {
                // SAFETY: closing the handle opened above, once.
                unsafe { (alsa.close)(pcm) };
                return None;
            }
            let (frames, incoming) = std::sync::mpsc::channel::<Vec<[i16; 2]>>();
            let handle = pcm as usize; // the handle moves to the thread that alone uses it
            std::thread::spawn(move || {
                let pcm = handle as Pcm;
                for chunk in incoming {
                    let mut rest = chunk.as_slice();
                    while !rest.is_empty() {
                        // SAFETY: `rest` holds whole interleaved stereo frames of i16.
                        let written = unsafe { (alsa.writei)(pcm, rest.as_ptr().cast(), rest.len() as c_ulong) };
                        if written >= 0 {
                            rest = &rest[(written as usize).min(rest.len())..];
                        } else {
                            // SAFETY: `pcm` is open until closed below.
                            if unsafe { (alsa.recover)(pcm, written as c_int, 1) } < 0 {
                                // SAFETY: closing the open handle, once.
                                unsafe { (alsa.close)(pcm) };
                                return;
                            }
                        }
                    }
                }
                // SAFETY: the sender is gone (Player dropped): close once.
                unsafe { (alsa.close)(pcm) };
            });
            Some(Player { frames })
        }

        pub fn play(&self, frames: Vec<[i16; 2]>) {
            let _ = self.frames.send(frames);
        }
    }
}

#[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
mod player {
    /// No audio output on this platform yet.
    #[derive(Debug)]
    pub struct Player;

    impl Player {
        pub fn start(_: u32) -> Option<Player> {
            None
        }
        pub fn play(&self, _: Vec<[i16; 2]>) {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The server's side of a sound session over the dynamic channel: its
    /// formats, a training, then sound; each gets the reply Windows waits for.
    #[test]
    fn sound_over_the_dynamic_channel() {
        use ironrdp::dvc::DvcProcessor as _;
        use ironrdp::rdpsnd::pdu::{ClientAudioOutputPdu, ServerAudioFormatPdu, ServerAudioOutputPdu, TrainingPdu, Version, Wave2Pdu};

        let mut channel = Dynamic::new();
        let send = |channel: &mut Dynamic, pdu: ServerAudioOutputPdu<'_>| -> Vec<ClientAudioOutputPdu> {
            let bytes = ironrdp::core::encode_vec(&pdu).unwrap();
            let replies = channel.process(7, &bytes).unwrap();
            replies
                .iter()
                .map(|r| {
                    let bytes = ironrdp::core::encode_vec(r.as_ref()).unwrap();
                    ironrdp::core::decode::<ClientAudioOutputPdu>(&bytes).unwrap()
                })
                .collect()
        };
        // Windows offers several formats; ours is among them.
        let mono = AudioFormat { n_channels: 1, n_avg_bytes_per_sec: RATE * 2, n_block_align: 2, ..FORMATS[0].clone() };
        let formats = vec![mono, FORMATS[0].clone()];
        let replies = send(&mut channel, ServerAudioOutputPdu::AudioFormat(ServerAudioFormatPdu { version: Version::V8, formats }));
        let Some(ClientAudioOutputPdu::AudioFormat(ours)) = replies.first() else { panic!("no format answer: {replies:?}") };
        assert_eq!(ours.formats, FORMATS, "only PCM 44.1 kHz stereo is taken");
        let replies = send(&mut channel, ServerAudioOutputPdu::Training(TrainingPdu { timestamp: 5, data: Vec::new() }));
        assert!(matches!(replies.as_slice(), [ClientAudioOutputPdu::TrainingConfirm(c)] if c.timestamp == 5));
        let wave = Wave2Pdu { timestamp: 9, format_no: 0, block_no: 3, audio_timestamp: 0, data: vec![0; 64].into() };
        let replies = send(&mut channel, ServerAudioOutputPdu::Wave2(wave));
        assert!(matches!(replies.as_slice(), [ClientAudioOutputPdu::WaveConfirm(c)] if c.timestamp == 9 && c.block_no == 3));
    }

    #[test]
    fn pcm_becomes_frames_at_the_servers_volume() {
        let pcm = [0x00, 0x40, 0x00, 0xc0, 0xff, 0x7f, 0x01, 0x80]; // 16384, -16384; 32767, -32767
        assert_eq!(frames(&pcm, [1.0, 1.0]), [[16384, -16384], [32767, -32767]]);
        assert_eq!(frames(&pcm, [0.5, 0.0]), [[8192, 0], [16383, 0]]);
        assert_eq!(frames(&pcm[..6], [1.0, 1.0]).len(), 1, "a broken last frame is left out");
    }

    #[test]
    fn resampling_keeps_the_pace_and_shape() {
        // 44.1 kHz to 48 kHz: a ramp stays a ramp, and 441 frames make 480.
        let mut pulled = 0;
        let mut resample = Resample::new(44_100, 48_000);
        resample.at = 1.0; // start by pulling the first frame
        let out: Vec<[f32; 2]> = (0..480)
            .map(|_| {
                resample.next(|| {
                    pulled += 1;
                    Some([pulled * 64, -pulled * 64])
                })
            })
            .collect();
        assert!((440..=442).contains(&pulled), "{pulled} source frames for 480 output frames");
        assert!(out.windows(2).all(|w| w[1][0] >= w[0][0] && w[1][1] <= w[0][1]), "still a ramp");
        // Nothing waiting: silence, not a repeat.
        let mut idle = Resample::new(44_100, 44_100);
        assert_eq!((0..3).map(|_| idle.next(|| None)).collect::<Vec<_>>(), [[0.0; 2]; 3]);
    }
}

//! Graphics Pipeline messages from the server, through IronRDP's client and
//! the helper's own handler and canvas, as main.rs drives them.
#![no_main]

#[allow(dead_code)]
#[path = "../../src/gfx.rs"]
mod gfx;

use ironrdp::dvc::DvcProcessor;
use ironrdp_egfx::client::GraphicsPipelineClient;

libfuzzer_sys::fuzz_target!(|messages: Vec<&[u8]>| {
    let (events, mut received) = tokio::sync::mpsc::unbounded_channel();
    let decoder = ironrdp_egfx::decode::OpenH264Decoder::new().unwrap();
    let mut client = GraphicsPipelineClient::new(Box::new(gfx::Handler::new(events)), Some(Box::new(decoder)));
    let _ = client.start(1);
    for message in messages {
        let _ = client.process(1, message);
    }
    let mut canvas: Option<gfx::Canvas> = None;
    while let Ok(event) = received.try_recv() {
        match event {
            gfx::Event::Reset(width, height) => {
                canvas = Some(match canvas.take() {
                    Some(old) => old.reset(width, height),
                    None => gfx::Canvas::new(width, height),
                })
            }
            event => {
                if let Some(canvas) = canvas.as_mut() {
                    canvas.apply(event);
                }
            }
        }
    }
});

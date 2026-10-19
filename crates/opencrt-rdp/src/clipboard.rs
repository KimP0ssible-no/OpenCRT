//! Clipboard text both ways over the CLIPRDR channel (plain Unicode text only).
//!
//! IronRDP calls the backend from inside the session's PDU processing, so it
//! cannot answer there: it queues what the channel should send next, and the
//! session loop hands that to the channel (see [`send`]).

use ironrdp::cliprdr::backend::{ClipboardMessage, CliprdrBackend};
use ironrdp::cliprdr::pdu::{
    ClipboardFormat, ClipboardFormatId, ClipboardGeneralCapabilityFlags, FileContentsRequest, FileContentsResponse,
    FormatDataRequest, FormatDataResponse, LockDataId,
};
use ironrdp::cliprdr::{Client, CliprdrClient, CliprdrSvcMessages};
use opencrt_rdp_proto::FromHelper;
use tokio::sync::mpsc::UnboundedSender;

use crate::Out;

const TEXT: ClipboardFormat = ClipboardFormat::new(ClipboardFormatId::CF_UNICODETEXT);

#[derive(Debug)]
pub struct Text {
    /// OpenCRT's clipboard text, offered to the server.
    local: Option<String>,
    /// What the channel should send next (handled by the session loop).
    queue: UnboundedSender<ClipboardMessage>,
    /// Text copied on the server goes straight to OpenCRT.
    out: Out,
}

ironrdp::core::impl_as_any!(Text);

impl Text {
    pub fn new(queue: UnboundedSender<ClipboardMessage>, out: Out) -> Self {
        Text { local: None, queue, out }
    }

    /// OpenCRT's clipboard changed: offer the text to the server.
    pub fn set_local(&mut self, text: String) {
        self.local = Some(text);
        let _ = self.queue.send(ClipboardMessage::SendInitiateCopy(vec![TEXT]));
    }
}

impl CliprdrBackend for Text {
    fn temporary_directory(&self) -> &str {
        "" // files are not offered either way
    }

    fn client_capabilities(&self) -> ClipboardGeneralCapabilityFlags {
        ClipboardGeneralCapabilityFlags::USE_LONG_FORMAT_NAMES
    }

    fn on_ready(&mut self) {}

    fn on_request_format_list(&mut self) {
        let formats = if self.local.is_some() { vec![TEXT] } else { Vec::new() };
        let _ = self.queue.send(ClipboardMessage::SendInitiateCopy(formats));
    }

    fn on_process_negotiated_capabilities(&mut self, _: ClipboardGeneralCapabilityFlags) {}

    fn on_remote_copy(&mut self, available_formats: &[ClipboardFormat]) {
        // Fetch the text at once, so it is on OpenCRT's clipboard when pasted.
        if available_formats.iter().any(|f| f.id == TEXT.id) {
            let _ = self.queue.send(ClipboardMessage::SendInitiatePaste(TEXT.id));
        }
    }

    fn on_format_data_request(&mut self, request: FormatDataRequest) {
        let response = match &self.local {
            Some(text) if request.format == TEXT.id => FormatDataResponse::new_unicode_string(text),
            _ => FormatDataResponse::new_error(),
        };
        let _ = self.queue.send(ClipboardMessage::SendFormatData(response));
    }

    fn on_format_data_response(&mut self, response: FormatDataResponse<'_>) {
        if !response.is_error()
            && let Ok(text) = response.to_unicode_string()
        {
            let _ = self.out.send(FromHelper::Clipboard(text));
        }
    }

    fn on_file_contents_request(&mut self, request: FileContentsRequest) {
        let _ = self.queue.send(ClipboardMessage::SendFileContentsResponse(FileContentsResponse::new_error(
            request.stream_id,
        )));
    }

    fn on_file_contents_response(&mut self, _: FileContentsResponse<'_>) {}

    fn on_lock(&mut self, _: LockDataId) {}

    fn on_unlock(&mut self, _: LockDataId) {}
}

/// The channel messages for a queued message (None for kinds never queued).
pub fn send(cliprdr: &mut CliprdrClient, message: ClipboardMessage) -> anyhow::Result<Option<CliprdrSvcMessages<Client>>> {
    Ok(Some(match message {
        ClipboardMessage::SendInitiateCopy(formats) => cliprdr.initiate_copy(&formats)?,
        ClipboardMessage::SendFormatData(data) => cliprdr.submit_format_data(data)?,
        ClipboardMessage::SendInitiatePaste(format) => cliprdr.initiate_paste(format)?,
        ClipboardMessage::SendFileContentsResponse(response) => cliprdr.submit_file_contents(response)?,
        _ => return Ok(None),
    }))
}

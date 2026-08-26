use tao::dpi::{LogicalSize, Size};
use tao::event::{Event, WindowEvent};
use tao::event_loop::{ControlFlow, EventLoop, EventLoopBuilder, EventLoopWindowTarget};
use tao::platform::run_return::EventLoopExtRunReturn;
use tao::window::{Window, WindowBuilder};
use wry::http::{HeaderMap, HeaderValue};
use wry::{PageLoadEvent, WebView, WebViewBuilder};
use xodus::models::live::{DAProperty, HostBridgeMessage};

#[cfg(target_os = "linux")]
const WEBKIT_DISABLE_DMABUF_RENDERER: &str = "WEBKIT_DISABLE_DMABUF_RENDERER";

type HandlerResult<T> = Result<T, Box<dyn std::error::Error>>;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct SessionId(u64);

pub enum HandlerControl<T> {
    Continue,
    Complete(T),
}

pub trait SessionHandler {
    type Output: std::fmt::Debug;

    fn bootstrap(&mut self, runtime: &mut RuntimeCommands) -> HandlerResult<()>;

    fn on_token(
        &mut self,
        session_id: SessionId,
        data: DAProperty,
        runtime: &mut RuntimeCommands,
    ) -> HandlerResult<HandlerControl<Self::Output>>;

    fn on_closed(
        &mut self,
        _session_id: SessionId,
        _runtime: &mut RuntimeCommands,
    ) -> HandlerResult<HandlerControl<Self::Output>> {
        Ok(HandlerControl::Continue)
    }
}

pub struct WebviewRequest {
    title: String,
    url: String,
    headers: HeaderMap,
}

pub struct RuntimeCommands {
    next_session_id: u64,
    actions: Vec<RuntimeAction>,
}

enum RuntimeAction {
    OpenSession {
        session_id: SessionId,
        request: WebviewRequest,
    },
    CloseSession(SessionId),
}

enum CustomEvent {
    OpenSession {
        session_id: SessionId,
        request: WebviewRequest,
    },
    HostGetContext(SessionId, String),
    Finish(SessionId),
    IpcCallback(SessionId, DAProperty),
}

struct RuntimeState<T: SessionHandler> {
    handler: T,
    next_session_id: u64,
    window: Option<Window>,
    active_session: Option<SessionId>,
    active_webview: Option<WebView>,
    result: Option<T::Output>,
    error: Option<String>,
}

impl RuntimeCommands {
    fn new(next_session_id: u64) -> Self {
        Self {
            next_session_id,
            actions: Vec::new(),
        }
    }

    pub fn open_session(&mut self, request: WebviewRequest) -> SessionId {
        let session_id = SessionId(self.next_session_id);
        self.next_session_id += 1;
        self.actions.push(RuntimeAction::OpenSession {
            session_id,
            request,
        });
        session_id
    }

    pub fn close_session(&mut self, session_id: SessionId) {
        self.actions.push(RuntimeAction::CloseSession(session_id));
    }
}

impl WebviewRequest {
    fn new(title: impl Into<String>, url: String, headers: HeaderMap) -> Self {
        Self {
            title: title.into(),
            url,
            headers,
        }
    }
}

pub fn login_request(
    client_id: String,
    market: String,
) -> Result<WebviewRequest, Box<dyn std::error::Error>> {
    let uid = uuid::Uuid::new_v4();
    let mut url = reqwest::Url::parse("https://login.live.com/ppsecure/InlineLogin.srf")?;
    url.query_pairs_mut()
        .append_pair("id", "80604")
        .append_pair("scid", "3")
        .append_pair("mkt", &market)
        .append_pair("Platform", "Windows10")
        .append_pair("clientid", &client_id)
        .append_pair("hosted", "1");

    let mut headers = HeaderMap::new();
    headers.insert("cxh-capabilities", HeaderValue::from_static(r#"{"PrivatePropertyBag":1,"PasswordlessConnect":1,"PreferAssociate":1,"ChromelessUI":0}"#));
    headers.insert(
        "cxh-correlationId",
        HeaderValue::from_str(&format!("{uid}"))?,
    );
    headers.insert("cxh-msaBinaryVersion", HeaderValue::from_static(r#"55"#));
    headers.insert(
        "cxh-identityClientBinaryVersion",
        HeaderValue::from_static(r#"3"#),
    );
    headers.insert(
        "cxh-osVersionInfo",
        HeaderValue::from_static(
            r#"{"platformId":2,"majorVersion":10,"minorVersion":0,"buildNumber":26100}"#,
        ),
    );
    headers.insert(
        "cxh-platform",
        HeaderValue::from_static(r#"CloudExperienceHost.Platform.DESKTOP"#),
    );
    headers.insert("cxh-protocol", HeaderValue::from_static(r#"TokenBroker"#));
    headers.insert("cxh-source", HeaderValue::from_static(r#"TokenBroker"#));
    headers.insert(
        "hostApp",
        HeaderValue::from_static(r#"CloudExperienceHost"#),
    );

    Ok(WebviewRequest::new("Xodus login", url.to_string(), headers))
}

pub fn finalize_request(url: String) -> Result<WebviewRequest, Box<dyn std::error::Error>> {
    let parsed = reqwest::Url::parse(&url)?;
    if parsed.scheme() != "https"
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "inline authentication URL must use HTTPS without credentials",
        )
        .into());
    }

    Ok(WebviewRequest::new(
        "Xodus login",
        parsed.to_string(),
        HeaderMap::new(),
    ))
}

pub fn run_sessions<T>(handler: T) -> HandlerResult<Option<T::Output>>
where
    T: SessionHandler,
{
    let mut event_loop: EventLoop<CustomEvent> = EventLoopBuilder::with_user_event().build();
    let proxy = event_loop.create_proxy();
    let mut state = RuntimeState {
        handler,
        next_session_id: 1,
        window: None,
        active_session: None,
        active_webview: None,
        result: None,
        error: None,
    };

    let mut commands = RuntimeCommands::new(state.next_session_id);
    state.handler.bootstrap(&mut commands)?;
    state.next_session_id = commands.next_session_id;
    dispatch_actions(&proxy, commands.actions)?;
    event_loop.run_return(|event, target, control_flow| {
        *control_flow = ControlFlow::Wait;

        match event {
            Event::UserEvent(CustomEvent::OpenSession {
                session_id,
                request,
            }) => {
                if let Err(err) = create_session(
                    target,
                    proxy.clone(),
                    &mut state,
                    session_id,
                    request,
                ) {
                    state.error = Some(err.to_string());
                }
            }
            Event::UserEvent(CustomEvent::Finish(session_id)) => {
                if state.active_session == Some(session_id)
                    && let Some(webview) = state.active_webview.as_ref()
                {
                    let _ = webview.evaluate_script("window.ipc.postMessage(JSON.stringify(ServerData))");
                }
            }
            Event::UserEvent(CustomEvent::HostGetContext(session_id, ctx)) => {
                if state.active_session == Some(session_id)
                    && let Some(webview) = state.active_webview.as_ref()
                {
                    let _ = webview.evaluate_script(&format!(r#"window["CloudExperienceHost.Bridge.dispatchMessage"](JSON.stringify({{"type": "callback", "value": {{ "name": "CloudExperienceHost.getContext", "args": ["CloudExperienceHost", "TokenBroker", "TokenBroker", "{{\"PrivatePropertyBag\":1,\"PasswordlessConnect\":1,\"PreferAssociate\":1,\"ChromelessUI\":0}}"], "context": "{ctx}"}}}}))"#));
                }
            }
            Event::UserEvent(CustomEvent::IpcCallback(session_id, data)) => {
                apply_handler_result(
                    &proxy,
                    target,
                    &mut state,
                    move |handler, runtime| handler.on_token(session_id, data, runtime),
                );
            }
            Event::WindowEvent {
                event: WindowEvent::CloseRequested,
                ..
            } => {
                if let Some(session_id) = state.active_session {
                    remove_session(&mut state, session_id);
                    apply_handler_result(&proxy, target, &mut state, move |handler, runtime| {
                        handler.on_closed(session_id, runtime)
                    });
                }
            }
            _ => {}
        }

        if state.error.is_some() || state.result.is_some() {
            *control_flow = ControlFlow::Exit;
        }
    });

    if let Some(error) = state.error {
        return Err(std::io::Error::other(error).into());
    }

    Ok(state.result)
}

fn dispatch_actions(
    proxy: &tao::event_loop::EventLoopProxy<CustomEvent>,
    actions: Vec<RuntimeAction>,
) -> HandlerResult<()> {
    for action in actions {
        match action {
            RuntimeAction::OpenSession {
                session_id,
                request,
            } => proxy
                .send_event(CustomEvent::OpenSession {
                    session_id,
                    request,
                })
                .map_err(|_| std::io::Error::other("failed to open session"))?,
            RuntimeAction::CloseSession(session_id) => {
                let _ = session_id;
            }
        }
    }

    Ok(())
}

fn apply_handler_result<T, F>(
    proxy: &tao::event_loop::EventLoopProxy<CustomEvent>,
    target: &EventLoopWindowTarget<CustomEvent>,
    state: &mut RuntimeState<T>,
    callback: F,
) where
    T: SessionHandler,
    F: FnOnce(&mut T, &mut RuntimeCommands) -> HandlerResult<HandlerControl<T::Output>>,
{
    let mut commands = RuntimeCommands::new(state.next_session_id);
    match callback(&mut state.handler, &mut commands) {
        Ok(HandlerControl::Continue) => {}
        Ok(HandlerControl::Complete(result)) => state.result = Some(result),
        Err(err) => state.error = Some(err.to_string()),
    }

    state.next_session_id = commands.next_session_id;
    apply_actions(proxy, target, state, commands.actions);
}

fn apply_actions<T>(
    proxy: &tao::event_loop::EventLoopProxy<CustomEvent>,
    target: &EventLoopWindowTarget<CustomEvent>,
    state: &mut RuntimeState<T>,
    actions: Vec<RuntimeAction>,
) where
    T: SessionHandler,
{
    for action in actions {
        match action {
            RuntimeAction::OpenSession {
                session_id,
                request,
            } => {
                if let Err(err) = create_session(target, proxy.clone(), state, session_id, request)
                {
                    state.error = Some(err.to_string());
                    break;
                }
            }
            RuntimeAction::CloseSession(session_id) => {
                remove_session(state, session_id);
                let _ = proxy;
            }
        }
    }
}

fn create_session<T: SessionHandler>(
    target: &EventLoopWindowTarget<CustomEvent>,
    proxy: tao::event_loop::EventLoopProxy<CustomEvent>,
    state: &mut RuntimeState<T>,
    session_id: SessionId,
    request: WebviewRequest,
) -> HandlerResult<()> {
    if state.window.is_none() {
        let window = WindowBuilder::new()
            .with_resizable(false)
            .with_title(&request.title)
            .with_inner_size(Size::Logical(LogicalSize::new(500.0, 700.0)))
            .build(target)?;
        state.window = Some(window);
    }

    let window = state
        .window
        .as_ref()
        .ok_or_else(|| std::io::Error::other("window was not initialized"))?;
    window.set_title(&request.title);

    let proxy_ipc = proxy.clone();
    let builder = WebViewBuilder::new()
            .with_url(&request.url)
            .with_user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64; MSAppHost/3.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.102 Safari/537.36 Edge/18.26100")
            .with_headers(request.headers)
            .with_initialization_script("window.external = {notify: window.ipc.postMessage }")
            .with_ipc_handler(move |request| {
                let body = request.body();
                let payload = serde_json::from_str::<DAProperty>(body);
                if let Ok(data) = payload {
                    if proxy_ipc
                        .send_event(CustomEvent::IpcCallback(session_id, data))
                        .is_err()
                    {
                        eprintln!("Failed to dispatch IPC token callback event");
                    }
                } else {
                    match serde_json::from_str::<HostBridgeMessage>(body) {
                        Ok(message) => {
                            if let Some(ctx) = message.get_context_invoke()
                                && proxy_ipc
                                    .send_event(CustomEvent::HostGetContext(
                                        session_id,
                                        ctx.to_string(),
                                    ))
                                    .is_err()
                            {
                                eprintln!("Failed to dispatch host context event");
                            }
                        }
                        Err(_) => {
                            eprintln!("Ignoring unsupported IPC payload");
                        }
                    }
                }
            })
            .with_on_page_load_handler(move |event, url| {
                if matches!(event, PageLoadEvent::Finished) && url.starts_with("https://login.live.com/ppsecure/post.srf")
                {
                    proxy.send_event(CustomEvent::Finish(session_id)).ok();
                }
            });

    #[cfg(target_os = "linux")]
    let webview = {
        use tao::platform::unix::WindowExtUnix;
        use wry::WebViewBuilderExtUnix;
        let vbox = window
            .default_vbox()
            .ok_or_else(|| std::io::Error::other("login window has no default GTK container"))?;
        builder.build_gtk(vbox)?
    };
    #[cfg(not(target_os = "linux"))]
    let webview = builder.build(&window)?;

    state.active_session = Some(session_id);
    state.active_webview = Some(webview);
    Ok(())
}

#[cfg(target_os = "linux")]
pub fn configure_linux_webkit_renderer() {
    let renderer_override = std::env::var_os(WEBKIT_DISABLE_DMABUF_RENDERER).is_some();
    let wayland_session = std::env::var_os("WAYLAND_DISPLAY").is_some();
    let nvidia_driver_present = std::path::Path::new("/proc/driver/nvidia/version").is_file();

    if should_disable_dmabuf_renderer(renderer_override, wayland_session, nvidia_driver_present) {
        // Safety. The CLI calls this before it starts the async runtime or WebKitGTK.
        unsafe {
            std::env::set_var(WEBKIT_DISABLE_DMABUF_RENDERER, "1");
        }
    }
}

#[cfg(target_os = "linux")]
fn should_disable_dmabuf_renderer(
    renderer_override: bool,
    wayland_session: bool,
    nvidia_driver_present: bool,
) -> bool {
    !renderer_override && wayland_session && nvidia_driver_present
}

fn remove_session<T: SessionHandler>(state: &mut RuntimeState<T>, session_id: SessionId) {
    if state.active_session == Some(session_id) {
        state.active_session = None;
        state.active_webview = None;
    }
}

#[cfg(test)]
mod tests {
    use super::{finalize_request, login_request};

    #[cfg(target_os = "linux")]
    use super::should_disable_dmabuf_renderer;

    #[test]
    fn login_request_encodes_query_parameters() {
        let request = login_request("client&id".to_string(), "en-US&x".to_string())
            .expect("login request must build");
        let url = reqwest::Url::parse(&request.url).expect("login URL must parse");
        let query: std::collections::HashMap<_, _> = url.query_pairs().into_owned().collect();

        assert_eq!(url.scheme(), "https");
        assert_eq!(url.host_str(), Some("login.live.com"));
        assert_eq!(query.get("id").map(String::as_str), Some("80604"));
        assert_eq!(query.get("scid").map(String::as_str), Some("3"));
        assert_eq!(query.get("mkt").map(String::as_str), Some("en-US&x"));
        assert_eq!(query.get("clientid").map(String::as_str), Some("client&id"));
        assert_eq!(query.get("hosted").map(String::as_str), Some("1"));
    }

    #[test]
    fn finalize_request_rejects_insecure_or_credentialed_urls() {
        for url in [
            "http://login.live.com/ppsecure/InlineConnect.srf",
            "https://user:password@login.live.com/ppsecure/InlineConnect.srf",
        ] {
            let error = match finalize_request(url.to_string()) {
                Ok(_) => panic!("inline authentication URL must fail closed"),
                Err(error) => error,
            };
            assert_eq!(
                error
                    .downcast_ref::<std::io::Error>()
                    .map(|error| error.kind()),
                Some(std::io::ErrorKind::InvalidData)
            );
        }
        assert!(finalize_request("/relative/path".to_string()).is_err());
    }

    #[test]
    fn finalize_request_preserves_secure_url() {
        let request = finalize_request(
            "https://login.live.com/ppsecure/InlineConnect.srf?mkt=en-US".to_string(),
        )
        .expect("secure inline authentication URL must remain supported");
        assert_eq!(
            request.url,
            "https://login.live.com/ppsecure/InlineConnect.srf?mkt=en-US"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn enables_the_workaround_for_wayland_nvidia_without_an_override() {
        assert!(should_disable_dmabuf_renderer(false, true, true));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn preserves_an_explicit_renderer_override() {
        assert!(!should_disable_dmabuf_renderer(true, true, true));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn leaves_non_wayland_sessions_unchanged() {
        assert!(!should_disable_dmabuf_renderer(false, false, true));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn leaves_systems_without_nvidia_unchanged() {
        assert!(!should_disable_dmabuf_renderer(false, true, false));
    }
}

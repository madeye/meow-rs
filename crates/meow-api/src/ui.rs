use axum::response::Html;

const UI_HTML: &str = include_str!("../static/index.html");

pub async fn serve_ui() -> Html<&'static str> {
    Html(UI_HTML)
}

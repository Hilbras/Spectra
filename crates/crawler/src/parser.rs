use scraper::{Html, Selector};

/// Parsed form data from an HTML page.
#[derive(Debug, Clone)]
pub struct ParsedForm {
    pub action: String,
    pub method: String,
    pub fields: Vec<ParsedFormField>,
}

/// A single form field.
#[derive(Debug, Clone)]
pub struct ParsedFormField {
    pub name: String,
    pub field_type: String,
    pub value: Option<String>,
    pub required: bool,
}

/// HTML parser for extracting links, forms, and other data from pages.
pub struct HtmlParser;

impl HtmlParser {
    /// Extracts all links from HTML content.
    pub fn extract_links(page_url: &str, html: &str) -> Vec<String> {
        let document = Html::parse_document(html);
        let mut links = Vec::new();

        // Extract from <a> tags
        if let Ok(selector) = Selector::parse("a[href]") {
            for element in document.select(&selector) {
                if let Some(href) = element.value().attr("href") {
                    if let Some(url) = resolve_url(page_url, href) {
                        links.push(url);
                    }
                }
            }
        }

        // Extract from <link> tags (stylesheets, etc.)
        if let Ok(selector) = Selector::parse("link[href]") {
            for element in document.select(&selector) {
                if let Some(href) = element.value().attr("href") {
                    if let Some(url) = resolve_url(page_url, href) {
                        links.push(url);
                    }
                }
            }
        }

        // Extract from <script> tags
        if let Ok(selector) = Selector::parse("script[src]") {
            for element in document.select(&selector) {
                if let Some(src) = element.value().attr("src") {
                    if let Some(url) = resolve_url(page_url, src) {
                        links.push(url);
                    }
                }
            }
        }

        // Extract from <img> tags
        if let Ok(selector) = Selector::parse("img[src]") {
            for element in document.select(&selector) {
                if let Some(src) = element.value().attr("src") {
                    if let Some(url) = resolve_url(page_url, src) {
                        links.push(url);
                    }
                }
            }
        }

        // Extract from <iframe> tags
        if let Ok(selector) = Selector::parse("iframe[src]") {
            for element in document.select(&selector) {
                if let Some(src) = element.value().attr("src") {
                    if let Some(url) = resolve_url(page_url, src) {
                        links.push(url);
                    }
                }
            }
        }

        links.sort();
        links.dedup();
        links
    }

    /// Extracts forms from HTML content.
    pub fn extract_forms(html: &str) -> Vec<ParsedForm> {
        let document = Html::parse_document(html);
        let mut forms = Vec::new();

        if let Ok(form_selector) = Selector::parse("form") {
            for form_element in document.select(&form_selector) {
                let action = form_element
                    .value()
                    .attr("action")
                    .unwrap_or("")
                    .to_string();

                let method = form_element
                    .value()
                    .attr("method")
                    .unwrap_or("GET")
                    .to_uppercase();

                let mut fields = Vec::new();

                // Extract input fields
                if let Ok(input_selector) = Selector::parse("input") {
                    for input in form_element.select(&input_selector) {
                        let name = input.value().attr("name").unwrap_or("").to_string();
                        if name.is_empty() {
                            continue;
                        }

                        let field_type = input.value().attr("type").unwrap_or("text").to_string();

                        let value = input.value().attr("value").map(String::from);
                        let required = input.value().attr("required").is_some();

                        fields.push(ParsedFormField {
                            name,
                            field_type,
                            value,
                            required,
                        });
                    }
                }

                // Extract textarea fields
                if let Ok(textarea_selector) = Selector::parse("textarea") {
                    for textarea in form_element.select(&textarea_selector) {
                        let name = textarea.value().attr("name").unwrap_or("").to_string();
                        if name.is_empty() {
                            continue;
                        }
                        fields.push(ParsedFormField {
                            name,
                            field_type: "textarea".to_string(),
                            value: None,
                            required: textarea.value().attr("required").is_some(),
                        });
                    }
                }

                // Extract select fields
                if let Ok(select_selector) = Selector::parse("select") {
                    for select in form_element.select(&select_selector) {
                        let name = select.value().attr("name").unwrap_or("").to_string();
                        if name.is_empty() {
                            continue;
                        }
                        fields.push(ParsedFormField {
                            name,
                            field_type: "select".to_string(),
                            value: None,
                            required: select.value().attr("required").is_some(),
                        });
                    }
                }

                forms.push(ParsedForm {
                    action,
                    method,
                    fields,
                });
            }
        }

        forms
    }

    /// Extracts meta tags from HTML content.
    pub fn extract_meta(html: &str) -> std::collections::HashMap<String, String> {
        let document = Html::parse_document(html);
        let mut meta = std::collections::HashMap::new();

        if let Ok(selector) = Selector::parse("meta") {
            for element in document.select(&selector) {
                if let Some(name) = element.value().attr("name") {
                    if let Some(content) = element.value().attr("content") {
                        meta.insert(name.to_string(), content.to_string());
                    }
                }
                if let Some(property) = element.value().attr("property") {
                    if let Some(content) = element.value().attr("content") {
                        meta.insert(property.to_string(), content.to_string());
                    }
                }
            }
        }

        meta
    }

    /// Extracts title from HTML content.
    pub fn extract_title(html: &str) -> Option<String> {
        let document = Html::parse_document(html);
        if let Ok(selector) = Selector::parse("title") {
            if let Some(element) = document.select(&selector).next() {
                return Some(element.text().collect::<String>());
            }
        }
        None
    }
}

/// Resolves a relative URL against a base URL.
fn resolve_url(base: &str, relative: &str) -> Option<String> {
    if relative.starts_with("data:") || relative.starts_with("javascript:") {
        return None;
    }

    if let Ok(base_url) = url::Url::parse(base) {
        if let Ok(resolved) = base_url.join(relative) {
            let scheme = resolved.scheme();
            if scheme == "http" || scheme == "https" {
                return Some(resolved.to_string());
            }
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_links_basic() {
        let html = r#"
            <html>
            <body>
                <a href="/page1">Page 1</a>
                <a href="https://example.com/page2">Page 2</a>
                <a href="https://other.com/page3">External</a>
            </body>
            </html>
        "#;

        let links = HtmlParser::extract_links("https://example.com/", html);
        assert!(links.contains(&"https://example.com/page1".to_string()));
        assert!(links.contains(&"https://example.com/page2".to_string()));
        assert!(links.contains(&"https://other.com/page3".to_string()));
    }

    #[test]
    fn extract_links_deduplication() {
        let html = r#"
            <html>
            <body>
                <a href="/page">Link 1</a>
                <a href="/page">Link 2</a>
            </body>
            </html>
        "#;

        let links = HtmlParser::extract_links("https://example.com/", html);
        assert_eq!(links.len(), 1);
    }

    #[test]
    fn extract_forms_basic() {
        let html = r#"
            <html>
            <body>
                <form action="/submit" method="POST">
                    <input type="text" name="username" required>
                    <input type="password" name="password">
                    <textarea name="comment"></textarea>
                    <select name="role">
                        <option value="user">User</option>
                    </select>
                </form>
            </body>
            </html>
        "#;

        let forms = HtmlParser::extract_forms(html);
        assert_eq!(forms.len(), 1);
        assert_eq!(forms[0].action, "/submit");
        assert_eq!(forms[0].method, "POST");
        assert_eq!(forms[0].fields.len(), 4);
        assert!(forms[0].fields[0].required);
        assert!(!forms[0].fields[1].required);
    }

    #[test]
    fn extract_title() {
        let html = "<html><head><title>Test Page</title></head></html>";
        assert_eq!(
            HtmlParser::extract_title(html),
            Some("Test Page".to_string())
        );
    }

    #[test]
    fn resolve_relative_url() {
        let base = "https://example.com/path/page";
        assert_eq!(
            resolve_url(base, "/other"),
            Some("https://example.com/other".to_string())
        );
        assert_eq!(
            resolve_url(base, "relative"),
            Some("https://example.com/path/relative".to_string())
        );
        assert_eq!(resolve_url(base, "data:text/html,..."), None);
    }
}

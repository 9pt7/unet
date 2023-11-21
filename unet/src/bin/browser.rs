use wasm_bindgen_futures::spawn_local;
use yew::prelude::*;

extern crate web_sys;

#[function_component]
fn App() -> Html {
    let counter = use_state(|| 100);
    let onclick = {
        let counter = counter.clone();
        move |_| {
            let value = *counter + 1;
            counter.set(value);
        }
    };

    html! {
        <div>
            <button {onclick}>{ "+1" }</button>
            <p>{ *counter }</p>
        </div>
    }
}

async fn serve() {
    unet::cloud::serve().await.unwrap();
}

fn main() {
    spawn_local(serve());
    yew::Renderer::<App>::new().render();
}

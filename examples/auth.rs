use http_types::{Method, Url};
use oauth_1a::*;
use std::io::{self, BufRead};

fn main() {
    let mut args = std::env::args().skip(1);
    let client_id = ClientId(args.next().unwrap());
    let client_secret = ClientSecret(args.next().unwrap());
    let mut key = SigningKey::without_token(client_secret);
    let mut data = OAuthData {
        client_id,
        token: None,
        signature_method: SignatureMethod::HmacSha1,
        nonce: Nonce::generate(),
    };
    let initiate = Url::parse("https://www.tumblr.com/oauth/request_token").unwrap();
    let callback = "http://localhost:1234/".to_string();
    let req = SignableRequest::new(Method::Post, initiate.clone(), Default::default());
    let authorization = data.authorization(req, AuthorizationType::RequestToken { callback }, &key);
    println!("Authorization: {}", authorization);
    let resp = attohttpc::post(initiate)
        .header("Authorization", authorization)
        .header("Content-Length", "0")
        .send()
        .unwrap()
        .text()
        .unwrap();
    println!("---\n{}", resp);
    data.regen_nonce();
    let token = receive_token(&mut data, &mut key, &resp).unwrap();
    println!("---\n{}", token.0);
    println!(
        "---\nhttps://www.tumblr.com/oauth/authorize?oauth_token={}",
        token.0
    );
    println!("---");
    let callback = Url::parse(io::stdin().lock().lines().next().unwrap().unwrap().trim()).unwrap();
    println!("---");
    let verifier = get_verifier(&callback).unwrap();
    println!("{}", verifier);
    let access = Url::parse("https://www.tumblr.com/oauth/access_token").unwrap();
    let req = SignableRequest::new(Method::Post, access.clone(), Default::default());
    let authorization = data.authorization(req, AuthorizationType::AccessToken { verifier }, &key);
    println!("---\nAuthorization: {}", authorization);
    let resp = attohttpc::post(access)
        .header("Authorization", authorization)
        .header("Content-Length", "0")
        .send()
        .unwrap()
        .text()
        .unwrap();
    println!("---\n{}", resp);
    data.regen_nonce();
    let token = receive_token(&mut data, &mut key, &resp).unwrap();
    println!("---\n{}", token.0);
    let following =
        Url::parse("https://api.tumblr.com/v2/blog/leo60228.tumblr.com/following").unwrap();
    let req = SignableRequest::new(Method::Get, following.clone(), Default::default());
    let authorization = data.authorization(req, AuthorizationType::Request, &key);
    println!("---\nAuthorization: {}", authorization);
    let resp = attohttpc::get(following)
        .header("Authorization", authorization)
        .header("Content-Length", "0")
        .send()
        .unwrap()
        .text()
        .unwrap();
    println!("---\n{}", resp);
}

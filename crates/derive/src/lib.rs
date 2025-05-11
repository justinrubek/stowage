use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, Data, DeriveInput, Fields};

#[proc_macro_derive(DecodeBytes)]
pub fn derive_decode_bytes(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let name = &input.ident;

    let fields = match &input.data {
        Data::Struct(data) => match &data.fields {
            Fields::Named(fields) => &fields.named,
            Fields::Unnamed(fields) => &fields.unnamed,
            Fields::Unit => panic!("Unit structs are not supported"),
        },
        _ => panic!("Only structs are supported"),
    };

    let field_decodes = fields.iter().map(|field| {
        let field_name = &field.ident;
        quote! {
            let #field_name = DecodeBytes::decode_bytes(buf)?;
        }
    });

    let field_names = fields.iter().map(|field| {
        let field_name = &field.ident;
        quote! { #field_name }
    });

    let expanded = quote! {
        impl DecodeBytes for #name {
            fn decode_bytes(buf: &mut BytesMut) -> Result<Self> {
                #(#field_decodes)*

                Ok(Self {
                    #(#field_names),*
                })
            }
        }
    };

    TokenStream::from(expanded)
}

#[proc_macro_derive(EncodeBytes)]
pub fn derive_encode_bytes(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let name = &input.ident;

    let fields = match &input.data {
        Data::Struct(data) => match &data.fields {
            Fields::Named(fields) => &fields.named,
            Fields::Unnamed(fields) => &fields.unnamed,
            Fields::Unit => panic!("Unit structs are not supported"),
        },
        _ => panic!("Only structs are supported"),
    };

    let field_encodes = fields.iter().map(|field| {
        let field_name = &field.ident;
        quote! {
            self.#field_name.encode_bytes(buf);
        }
    });

    let expanded = quote! {
        impl EncodeBytes for #name {
            fn encode_bytes(&self, buf: &mut BytesMut) {
                #(#field_encodes)*
            }
        }
    };

    TokenStream::from(expanded)
}

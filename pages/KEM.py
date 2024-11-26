import streamlit as st
from algorithms.KEM import B64

st.set_page_config(page_title="Key Encapsulation Mechanisms", page_icon="🔑")

def main():
    st.title("🔑 Key Encapsulation Mechanisms")

    st.write("This page demonstrates Key Encapsulation Mechanisms (KEM).")

    if st.button("Generate Key"):
        key = B64.demo_kem_algorithm()
        st.success(f"Generated Key:\n\n{key}")

if __name__ == "__main__":
    main()

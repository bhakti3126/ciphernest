
import os
import requests
import streamlit as st
from dotenv import load_dotenv

load_dotenv()

API_URL = os.getenv("CIPHERNEST_API_URL", "http://127.0.0.1:8000").rstrip("/")

st.set_page_config(
    page_title="CipherNest | Secure Cloud Storage",
    page_icon="🔐",
    layout="wide",
)

st.markdown("""
<style>
.stApp {
    background: linear-gradient(135deg, #060c15, #0b1730);
    color: #eaf7ff;
}
.block-container {
    max-width: 1100px;
    padding-top: 2rem;
}
h1, h2, h3, p, label {
    color: #eaf7ff !important;
}
.hero {
    padding: 28px;
    border: 1px solid #174b70;
    border-radius: 18px;
    background: linear-gradient(120deg, #0c2036, #102c50);
    margin-bottom: 24px;
}
.hero h1 {
    color: #00e5ff !important;
    margin-bottom: 8px;
}
div.stButton > button {
    background: linear-gradient(90deg, #007eae, #2563eb);
    color: white;
    border: 0;
    border-radius: 10px;
    min-height: 44px;
    font-weight: 600;
    width: 100%;
}
div.stButton > button:hover {
    border: 1px solid #00e5ff;
    color: white;
}
div[data-testid="stFileUploader"] {
    border: 1px dashed #1688b5;
    border-radius: 12px;
    padding: 12px;
}
.panel {
    background: #0c1b2d;
    border: 1px solid #173b59;
    border-radius: 14px;
    padding: 20px;
    margin-bottom: 16px;
}
.small-note {
    color: #a6bfd4;
    font-size: 14px;
}
</style>
""", unsafe_allow_html=True)


def api_error(response):
    try:
        body = response.json()
        return body.get("detail", body.get("message", response.text))
    except Exception:
        return response.text or f"HTTP error {response.status_code}"


def get_files():
    response = requests.get(f"{API_URL}/api/files", timeout=30)
    response.raise_for_status()
    return response.json().get("files", [])


st.markdown("""
<div class="hero">
    <h1>🔐 CipherNest</h1>
    <p>Private cloud storage with encrypted file blocks.</p>
    <p class="small-note">
        Upload a file securely, or retrieve an existing file and download
        its original contents.
    </p>
</div>
""", unsafe_allow_html=True)

# Check the existing FastAPI backend.
try:
    health_response = requests.get(f"{API_URL}/health", timeout=5)
    health_response.raise_for_status()
    backend_online = True
except requests.RequestException:
    backend_online = False

if backend_online:
    st.success("Backend connected")
else:
    st.error(
        "CipherNest backend is not reachable. Start your existing FastAPI "
        "backend first, then refresh this page."
    )
    st.caption(f"Backend address: {API_URL}")

upload_tab, download_tab = st.tabs(["⬆️ Upload File", "⬇️ Download File"])

with upload_tab:
    st.markdown("### Upload and encrypt")
    st.write(
        "Choose a file. CipherNest sends it to your existing backend, "
        "which encrypts the file and stores its encrypted blocks in your configured storage."
    )

    uploaded_file = st.file_uploader(
        "Choose a file to protect",
        key="ciphernest_upload",
    )

    if uploaded_file:
        st.caption(
            f"Selected: {uploaded_file.name} · "
            f"{uploaded_file.size:,} bytes"
        )

    if st.button(
        "🔒 Upload & Encrypt",
        disabled=(not backend_online or uploaded_file is None),
        key="upload_button",
    ):
        try:
            with st.spinner("Encrypting and securely storing your file..."):
                response = requests.post(
                    f"{API_URL}/api/files/upload",
                    files={
                        "file": (
                            uploaded_file.name,
                            uploaded_file.getvalue(),
                            uploaded_file.type or "application/octet-stream",
                        )
                    },
                    timeout=(10, 600),
                )

            if response.ok:
                result = response.json()
                file_info = result.get("file", {})
                st.success("File encrypted and uploaded successfully!")
                st.write(f"**Filename:** {file_info.get('original_filename', uploaded_file.name)}")
                st.write(f"**Encryption:** {file_info.get('cipher', 'AES-256-GCM')}")
                st.write(f"**Encrypted blocks:** {file_info.get('total_chunks', 'N/A')}")
                st.write(f"**File ID:** `{file_info.get('file_id', 'N/A')}`")
                st.info("Open the Download File tab to retrieve your file.")
            else:
                st.error(f"Upload failed: {api_error(response)}")

        except requests.RequestException as error:
            st.error(f"Could not contact the backend: {error}")

with download_tab:
    st.markdown("### Retrieve your files")
    st.write(
        "Refresh the list, select a stored file, and download the reconstructed original."
    )

    if st.button(
        "↻ Refresh File List",
        disabled=not backend_online,
        key="refresh_button",
    ):
        st.session_state["refresh_files"] = True

    if backend_online:
        try:
            files = get_files()

            if not files:
                st.info("No stored files were found.")
            else:
                options = {}
                for item in files:
                    file_id = item.get("file_id")
                    if file_id:
                        filename = item.get("original_filename") or "Unnamed file"
                        size = item.get("original_size") or 0
                        options[file_id] = f"{filename} ({size:,} bytes)"

                if options:
                    selected_id = st.selectbox(
                        "Select a file",
                        options=list(options.keys()),
                        format_func=lambda file_id: options[file_id],
                        key="selected_file_id",
                    )

                    if st.button("⬇️ Decrypt & Download", key="download_button"):
                        try:
                            with st.spinner("Retrieving and verifying encrypted blocks..."):
                                response = requests.get(
                                    f"{API_URL}/api/files/{selected_id}/download",
                                    timeout=(10, 600),
                                )

                            if response.ok:
                                selected = next(
                                    item for item in files
                                    if item.get("file_id") == selected_id
                                )
                                filename = selected.get(
                                    "original_filename", "downloaded_file"
                                )
                                content_type = selected.get(
                                    "content_type", "application/octet-stream"
                                )

                                st.success("File recovered successfully!")
                                st.download_button(
                                    "Save original file",
                                    data=response.content,
                                    file_name=filename,
                                    mime=content_type,
                                    key=f"save_{selected_id}",
                                )
                            else:
                                st.error(f"Download failed: {api_error(response)}")

                        except requests.RequestException as error:
                            st.error(f"Could not download the file: {error}")
                else:
                    st.warning("The file list did not contain any valid file IDs.")

        except requests.RequestException as error:
            st.error(f"Could not load the file list: {error}")

st.markdown("---")
st.caption("CipherNest · Encrypted storage · Existing backend and storage configuration")

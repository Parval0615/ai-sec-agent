from langchain_community.document_loaders import PyPDFLoader
from langchain_text_splitters import RecursiveCharacterTextSplitter
from langchain_community.embeddings import HuggingFaceEmbeddings
from langchain_community.vectorstores import FAISS
from langchain_core.vectorstores import VectorStoreRetriever
from core.config import *
import os

def init_rag_retriever(pdf_path: str = "docs/test.pdf") -> VectorStoreRetriever:
    if not os.path.exists(pdf_path):
        raise FileNotFoundError("请把 test.pdf 放在 docs 目录下")

    loader = PyPDFLoader(pdf_path)
    docs = loader.load()
    splitter = RecursiveCharacterTextSplitter(chunk_size=CHUNK_SIZE, chunk_overlap=CHUNK_OVERLAP)
    split_docs = splitter.split_documents(docs)
    embeddings = HuggingFaceEmbeddings(model_name=EMBEDDING_MODEL)
    vector_store = FAISS.from_documents(split_docs, embeddings)
    return vector_store.as_retriever(search_kwargs={"k": TOP_K})

def rag_query(retriever: VectorStoreRetriever, query: str) -> str:
    docs = retriever.invoke(query)
    return "\n".join([doc.page_content for doc in docs]) if docs else "未找到内容"
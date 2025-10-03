# ner.py
from transformers import AutoTokenizer, AutoModelForTokenClassification, pipeline

# ---------- Load NER Model ----------
tokenizer = AutoTokenizer.from_pretrained("dslim/bert-base-NER")
model = AutoModelForTokenClassification.from_pretrained("dslim/bert-base-NER")
ner_pipeline = pipeline("ner", model=model, tokenizer=tokenizer, aggregation_strategy="simple")


# ---------- Existing chunking function ----------
def chunk_text(text, max_tokens=500):
    words = text.split()
    chunks = []
    current_chunk = []
    current_len = 0

    for word in words:
        token_len = len(tokenizer.tokenize(word))
        if current_len + token_len > max_tokens:
            chunks.append(" ".join(current_chunk))
            current_chunk = [word]
            current_len = token_len
        else:
            current_chunk.append(word)
            current_len += token_len

    if current_chunk:
        chunks.append(" ".join(current_chunk))
    return chunks


# ---------- Wrapper function for API ----------
def redact_file(input_path, output_path):
    """
    Reads a text file from input_path, redacts NER entities, writes redacted text to output_path.
    """
    with open(input_path, "r", encoding="utf-8") as f:
        lines = f.readlines()

    redacted_lines = []
    for line in lines:
        line = line.strip()
        if not line:
            redacted_lines.append("")  # preserve blank lines
            continue
        chunks = chunk_text(line)  # split long lines into max-token chunks
        redacted_line = ""
        for chunk in chunks:
            entities = ner_pipeline(chunk)
            print(entities)  # you can remove this if you don't want logging
            for ent in entities:
                chunk = chunk.replace(ent['word'], "[REDACTED]")
            redacted_line += chunk + " "
        redacted_lines.append(redacted_line.strip())

    with open(output_path, "w", encoding="utf-8") as f:
        f.write("\n".join(redacted_lines))

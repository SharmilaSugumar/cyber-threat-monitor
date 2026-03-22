from app.services.preprocessor import LogPreprocessor

pp = LogPreprocessor()
logs = pp.process_file('../data/sample_logs.txt')

print(f"Total logs parsed: {len(logs)}")
print("\nFirst log:")
print(logs[0])

print("\nFirst sequence:")
sequences = pp.build_sequences(logs)
print(sequences[0]['text'])
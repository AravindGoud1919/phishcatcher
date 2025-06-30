import pandas as pd

# Load your original legitimate URLs
df = pd.read_csv("dataset/legitimate_urls.csv")

# Strip whitespace and make sure all URLs are lowercase (optional but good for consistency)
df['url'] = df['url'].astype(str).str.strip().str.lower()

# Create a new list to store all URLs
enhanced_rows = []

for _, row in df.iterrows():
    url = row['url']
    label = row['label']

    enhanced_rows.append({'url': url, 'label': label})

    # If URL contains 'www.', add a duplicate without 'www.'
    if '://www.' in url:
        url_without_www = url.replace('://www.', '://')
        enhanced_rows.append({'url': url_without_www, 'label': label})

# Convert to DataFrame
enhanced_df = pd.DataFrame(enhanced_rows).drop_duplicates()

# Save back to CSV (overwrite or save as new)
enhanced_df.to_csv("dataset/legitimate_urls_expanded.csv", index=False)

print(f"✅ Done. Total rows after enhancement: {len(enhanced_df)}")

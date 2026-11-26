"""Train the contextual URL model from the attributed CC BY 4.0 Kaggle dataset."""

import argparse
import csv
import json
from pathlib import Path

from app.dataset_model import FEATURE_NAMES, dataset_partition, model_score, url_features
from app.security import normalize_target
from scripts.evaluate_datasets import open_csv


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dataset", type=Path)
    parser.add_argument("--output", type=Path, default=Path("app/url_model.json"))
    args = parser.parse_args()
    from sklearn.linear_model import LogisticRegression
    from sklearn.preprocessing import StandardScaler

    training, validation = [], []
    with open_csv(args.dataset, "final_dataset.csv") as stream:
        reader = csv.DictReader(stream)
        if not {"url", "label"}.issubset(reader.fieldnames or []):
            parser.error("Expected the attributed dataset's url and label columns.")
        for row in reader:
            if row["label"] not in {"0", "1"}:
                continue
            try:
                target = normalize_target(row["url"], resolve=False)
            except ValueError:
                continue
            bucket = dataset_partition(target["domain"])
            rows = training if bucket < 7 else validation if bucket == 7 else None
            if rows is not None:
                rows.append((url_features(target), int(row["label"])))
    train_x, train_y = zip(*training)
    scaler = StandardScaler().fit(train_x)
    classifier = LogisticRegression(class_weight="balanced", max_iter=200).fit(scaler.transform(train_x), train_y)
    weights = classifier.coef_[0] / scaler.scale_
    result = {
        "source": "elifzelik/phishing-url-features-dataset",
        "features": FEATURE_NAMES,
        "coefficients": weights.tolist(),
        "intercept": float(classifier.intercept_[0] - weights @ scaler.mean_),
        "training_rows": len(training),
        "validation_rows": len(validation),
    }
    benign = sorted(model_score(row, result) for row, label in validation if label == 0)
    result["threshold"] = max(0.5, min(1.0, benign[round((len(benign) - 1) * 0.95)] + 0.00001))
    args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(f"Trained using {len(training):,} rows. Validation {len(validation):,}. Threshold {result['threshold']:.4f}.")


if __name__ == "__main__":
    main()

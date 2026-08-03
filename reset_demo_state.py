import os

FILES_TO_RESET = [
    "logs/access.log",
    "logs/deployed_canaries.json",
    "logs/containment_actions.json",
]


def reset_state():
    for filepath in FILES_TO_RESET:
        if os.path.exists(filepath):
            os.remove(filepath)
            print(f"Removed {filepath}")
        else:
            print(f"{filepath} did not exist, skipping")
    print("\nDemo state reset. Restart mock_target.py before running a new scenario.")


if __name__ == "__main__":
    reset_state()
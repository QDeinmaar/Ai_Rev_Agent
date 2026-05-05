import os
from Ai_Rev_Engin.Data_Base.db_manager import DB_PATH

if os.path.exists(DB_PATH):
    os.remove(DB_PATH)
    print(f"✅ Deleted: {DB_PATH}")
else:
    print("Database doesn't exist")

print("Database reset complete")
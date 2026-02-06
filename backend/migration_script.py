import sqlite3

def migrate_database():
    conn = sqlite3.connect('documents.db')
    cursor = conn.cursor()
    
    try:
        # Add file_hash column if it doesn't exist
        cursor.execute("""
            ALTER TABLE document 
            ADD COLUMN file_hash VARCHAR(64)
        """)
        conn.commit()
        print("✅ Migration successful! file_hash column added.")
    except sqlite3.OperationalError as e:
        if "duplicate column name" in str(e):
            print("✅ Column already exists, no migration needed.")
        else:
            print(f"❌ Error: {e}")
    finally:
        conn.close()

if __name__ == '__main__':
    migrate_database()


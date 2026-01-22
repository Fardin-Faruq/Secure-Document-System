import sqlite3

conn = sqlite3.connect('instance/ids_database.db')
cursor = conn.cursor()
cursor.execute('DELETE FROM access_log')
conn.commit()
conn.close()
print("✅ Old activity logs cleared successfully!")
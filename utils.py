
## HorusEye - Utility Functions ##

 ## Helpers for time parsing and general formatting. ## 


from datetime import datetime


def parse_timestamp(ts_str: str, year: int) -> datetime:
    
    try:
        full_str = f"{year} {ts_str}"
        return datetime.strptime(full_str, "%Y %b %d %H:%M:%S")
    except ValueError:
        return datetime.utcnow()  # Fallback to current UTC time


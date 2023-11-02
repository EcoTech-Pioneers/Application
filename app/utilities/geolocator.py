from geopy.geocoders import ArcGIS

def generate_coordinates(location = ""):
    geolocator = ArcGIS()
    location = location + ' ,Kenya'
    try:
        location_info = geolocator.geocode(location)
        if location_info:
            latitude = location_info.latitude
            longitude = location_info.longitude
            return (latitude, longitude)
    
    except Exception as e:
        return None

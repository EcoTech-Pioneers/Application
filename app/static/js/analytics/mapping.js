var map = L.map('map').setView([-1.31, 36.87], 13);
var tileLayer = L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
	maxZoom: 19,
}).addTo(map);
var redMarkerIcon = L.icon({
	iconUrl: 'https://raw.githubusercontent.com/pointhi/leaflet-color-markers/master/img/marker-icon-2x-red.png',
	iconSize: [25, 41],
	iconAnchor: [12, 41],
	popupAnchor: [1, -34],
});
var greenCircleOptions = {
	color: 'green',
	fillColor: 'green',
	weight: 1,
	fillOpacity: 0.2,
};
var locations = [];
var streetLayer = L.tileLayer('https://server.arcgisonline.com/ArcGIS/rest/services/World_Street_Map/MapServer/tile/{z}/{y}/{x}', {
	attribution: 'Esri - World Street Map',
});

var satelliteLayer = L.tileLayer('https://server.arcgisonline.com/ArcGIS/rest/services/World_Imagery/MapServer/tile/{z}/{y}/{x}', {
	attribution: 'Esri - World Imagery',
});

var topoLayer = L.tileLayer('https://server.arcgisonline.com/ArcGIS/rest/services/World_Topo_Map/MapServer/tile/{z}/{y}/{x}', {
	attribution: 'Esri - World Topo Map',
});

// Define additional layers
var outdoorsLayer = L.tileLayer(`https://tile.thunderforest.com/outdoors/{z}/{x}/{y}.png?apikey=01d82ad201324aed8704e82e68750aa1`, {
	attribution: 'Map data &copy; <a href="https://www.thunderforest.com/">Thunderforest</a>',
});
var cycleLayer = L.tileLayer(`https://tile.thunderforest.com/cycle/{z}/{x}/{y}.png?apikey=01d82ad201324aed8704e82e68750aa1`, {
	attribution: 'Map data &copy; <a href="https://www.thunderforest.com/">Thunderforest</a>',
});
var transportLayer = L.tileLayer(`https://tile.thunderforest.com/transport/{z}/{x}/{y}.png?apikey=01d82ad201324aed8704e82e68750aa1`, {
	attribution: 'Map data &copy; <a href="https://www.thunderforest.com/">Thunderforest</a>',
});
var landscapeLayer = L.tileLayer(`https://tile.thunderforest.com/landscape/{z}/{x}/{y}.png?apikey=01d82ad201324aed8704e82e68750aa1`, {
	attribution: 'Map data &copy; <a href="https://www.thunderforest.com/">Thunderforest</a>',
});
var pioneerLayer = L.tileLayer(`https://tile.thunderforest.com/pioneer/{z}/{x}/{y}.png?apikey=01d82ad201324aed8704e82e68750aa1`, {
	attribution: 'Map data &copy; <a href="https://www.thunderforest.com/">Thunderforest</a>',
});

// Add the layers to the map
map.addLayer(streetLayer);
map.addLayer(satelliteLayer);
map.addLayer(topoLayer);
map.addLayer(outdoorsLayer);
map.addLayer(cycleLayer);
map.addLayer(transportLayer);
map.addLayer(landscapeLayer);
map.addLayer(pioneerLayer);

// Define a baseLayers object for the layer control
var baseLayers = {
	'Street Map': streetLayer,
	'Satellite Imagery': satelliteLayer,
	'Topographic Map': topoLayer,
	'Outdoors': outdoorsLayer,
	'Cycle': cycleLayer,
	'Transport': transportLayer,
	'Landscape': landscapeLayer,
	'Pioneer': pioneerLayer,
};

// Create the layer control
L.control.layers(baseLayers).addTo(map);

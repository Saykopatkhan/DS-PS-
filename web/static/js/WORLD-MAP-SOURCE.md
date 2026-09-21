# Local country boundaries

Made with [Natural Earth](https://www.naturalearthdata.com/).
Dataset: 1:110m Admin 0 Countries, public domain.
[Terms of use](https://www.naturalearthdata.com/about/terms-of-use/).

Source revision: `ca96624a56bd078437bca8184e78163e5039ad19` in
[natural-earth-vector](https://github.com/nvkelso/natural-earth-vector/blob/ca96624a56bd078437bca8184e78163e5039ad19/geojson/ne_110m_admin_0_countries.geojson).

`scripts/update_world_map.py` retains the original geometries and country names,
removes unused properties, and writes `world.geojson`. Run it only when rebuilding
the asset; the running application serves the checked-in file locally.

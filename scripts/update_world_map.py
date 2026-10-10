"""Rebuild the local country map from a pinned Natural Earth public-domain source."""
import json
from pathlib import Path
from urllib.request import urlopen

REVISION = 'ca96624a56bd078437bca8184e78163e5039ad19'
SOURCE = (f'https://raw.githubusercontent.com/nvkelso/natural-earth-vector/{REVISION}/'
          'geojson/ne_110m_admin_0_countries.geojson')


def main():
    with urlopen(SOURCE, timeout=60) as response:
        source = json.load(response)
    features = [{
        'type': 'Feature',
        'properties': {'name': feature['properties']['NAME']},
        'geometry': feature['geometry'],
    } for feature in source['features']]
    assert len(features) > 150, 'Incomplete country dataset'
    destination = Path(__file__).resolve().parents[1] / 'web/static/js/world.geojson'
    destination.write_text(json.dumps({'type': 'FeatureCollection', 'features': features},
                                     ensure_ascii=False, separators=(',', ':')) + '\n', encoding='utf-8')
    print(f'Wrote {len(features)} country features to {destination}')


if __name__ == '__main__':
    main()

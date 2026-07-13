'use strict';
'require view';
'require uci';

// Embeds meow's built-in web panel (served by the meow REST API at /ui)
// instead of reimplementing a dashboard in LuCI. The panel port comes from
// the `panel_port` UCI option, which must match the `external-controller`
// port in the meow YAML config.

return view.extend({
	load: function() {
		return uci.load('meow');
	},

	render: function() {
		var port = uci.get('meow', 'main', 'panel_port') || '9090';
		var url = window.location.protocol + '//' +
			window.location.hostname + ':' + port + '/ui';

		return E('div', { 'class': 'cbi-map' }, [
			E('h2', {}, _('meow Panel')),
			E('div', { 'class': 'cbi-map-descr' }, [
				_('Built-in web panel served by the meow REST API. '),
				E('a', { 'href': url, 'target': '_blank', 'rel': 'noopener' },
					_('Open in a new tab')),
				' — ', url
			]),
			E('iframe', {
				'src': url,
				'style': 'width: 100%; min-height: 75vh; border: none;' +
					' border-radius: 3px; background: #0f1923;'
			})
		]);
	},

	handleSave: null,
	handleSaveApply: null,
	handleReset: null
});

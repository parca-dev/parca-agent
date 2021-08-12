local agent = (import 'main.jsonnet');

std.manifestYamlStream([
  agent[name]
  for name in std.objectFields(agent)
  if agent[name] != null
])

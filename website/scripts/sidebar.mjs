// Builds Starlight's sidebar from site.manifest.json so the manifest is the
// single place a page is placed in the navigation.
export function sidebarFromManifest(manifest) {
  const byGroup = new Map(manifest.groups.map((g) => [g, []]));
  for (const page of manifest.pages) {
    const items = byGroup.get(page.group);
    if (!items) throw new Error(`sidebar: page ${page.route} uses group "${page.group}", which is not declared in manifest.groups`);
    items.push(page);
  }
  return manifest.groups.map((label) => ({
    label,
    items: byGroup.get(label)
      .sort((a, b) => a.order - b.order)
      .map((p) => ({ label: p.label, slug: p.route })),
  }));
}

<div>
{% if func['comment'] %}
  <div>
  {{ func['comment']['brief'] }}
  </div>
{% endif %}
{{ func['result']['type_spelling'] }} {{ func['spelling'] }}
</div>

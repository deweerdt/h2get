<div>
{% if func['comment'] %}
  <div>
  {{ func['comment']['brief'] }}
  </div>
{% endif %}
{{ func['result']['type_spelling'] }} {{ func['spelling'] }}({% if func['params'] %}
<ul>
{% for param in func['params'] %}
  <li>{{ param['type_spelling'] }} {{ param['spelling'] }}{% if func['comment'] %}: {{ func['comment']['params'][param['spelling']] }}{% endif %}</li>
{% endfor %}
</ul>
{% endif %})
</div>

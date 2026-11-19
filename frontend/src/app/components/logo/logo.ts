
import { Component, input } from '@angular/core';

@Component({
  selector: 'app-logo',
  template: `
    <svg
      [attr.width]="size()"
      [attr.height]="size()"
      viewBox="0 0 24 24"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      aria-hidden="true"
    >
      <path
        d="M12 2l8 3v6c0 5-3.4 8.6-8 11-4.6-2.4-8-6-8-11V5l8-3z"
        fill="currentColor"
      />
      <circle cx="12" cy="10" r="2.3" fill="#ffffff" />
      <path
        d="M12 12.2v4.6"
        stroke="#ffffff"
        stroke-width="2"
        stroke-linecap="round"
      />
    </svg>
  `,
})
export class Logo {
  readonly size = input<number>(28);
}

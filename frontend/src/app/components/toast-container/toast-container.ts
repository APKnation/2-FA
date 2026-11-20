import { Component } from '@angular/core';
import { ToastService, Toast } from '../../services/toast.service';

@Component({
  selector: 'app-toast-container',
  templateUrl: './toast-container.html',
})
export class ToastContainer {
  constructor(protected toast: ToastService) {}

  trackById(index: number, item: Toast): number {
    return item.id;
  }
}

import { Component, Input, EventEmitter, OnInit, Output } from '@angular/core';
import { FormsModule } from "@angular/forms";
import { ToastrService } from 'ngx-toastr';
import { AccountService } from '../_services/account.service';

@Component({
  selector: 'app-register',
  templateUrl: './register.component.html',
  styleUrls: ['./register.component.css']
})
export class RegisterComponent implements OnInit {
  model: any = {}
  @Output() cancelRegister = new EventEmitter();
  constructor(private accountService: AccountService,
  private toastr:ToastrService) { }
  ngOnInit(): void {
  }
  register() {
    this.accountService.register(this.model).subscribe(
      Response => {
        console.log(Response);
        this.cancel();
      },
      error => {
        this.toastr.error(error.error);
      }
    )
  }
  cancel() {
    this.cancelRegister.emit(false);
  }
}
